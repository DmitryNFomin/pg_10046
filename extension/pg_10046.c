/*
 * pg_10046.c - PostgreSQL extension for Oracle 10046-style tracing
 *
 * Captures SQL text, bind variables, plan text, node mapping, and
 * periodic wait event sampling during execution.
 *
 * Features:
 * - SQL and bind capture at planning time
 * - Plan tree structure output
 * - Node mapping with Instrumentation pointers
 * - PERIODIC SAMPLING: Every X ms, captures current wait_event_info
 *   and associates it with the currently executing node
 * - Final execution statistics per node
 *
 * Copyright (c) 2024
 */

#include "postgres.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>

#include "commands/explain.h"
#include "access/relscan.h"
#include "executor/executor.h"
#include "executor/instrument.h"
#include "executor/hashjoin.h"
#include "nodes/execnodes.h"
#include "miscadmin.h"
#include "optimizer/planner.h"
#include "parser/parsetree.h"
#include "pgstat.h"
#include "storage/proc.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/timeout.h"
#include "utils/timestamp.h"
#include "utils/lsyscache.h"
#include "utils/datum.h"
#include "utils/tuplesort.h"
#include "utils/rel.h"
#include "catalog/pg_type.h"
#include "catalog/pg_am.h"

PG_MODULE_MAGIC;

void		_PG_init(void);
void		_PG_fini(void);

/* Forward declarations for eBPF daemon communication */
static void write_trace(const char *fmt, ...) pg_attribute_printf(1, 2);
static void start_ebpf_trace(void);
static void stop_ebpf_trace(void);

/* Saved hook values */
static planner_hook_type prev_planner_hook = NULL;
static ExecutorStart_hook_type prev_ExecutorStart = NULL;
static ExecutorRun_hook_type prev_ExecutorRun = NULL;
static ExecutorEnd_hook_type prev_ExecutorEnd = NULL;

/* GUC variables */
static bool pg10046_enabled = false;
static bool pg10046_ebpf_enabled = false;  /* Also start eBPF IO tracing */
static char *pg10046_trace_dir = NULL;
static char *pg10046_daemon_socket = NULL;  /* Default: /var/run/pg_10046.sock */
static int pg10046_sample_interval_ms = 10;  /* Sample every 10ms by default */
static int pg10046_progress_interval_tuples = 0;  /* Debug: emit PROGRESS every N tuples (0=disabled) */

#define DEFAULT_DAEMON_SOCKET "/var/run/pg_10046.sock"

/* Maximum depth of node stack for tracking current execution */
#define MAX_NODE_STACK_DEPTH 64

/* Maximum number of nodes we can wrap */
#define MAX_WRAPPED_NODES 256

/* Storage for original ExecProcNode pointers and node tracking state */
typedef struct WrappedNode {
	PlanState  *node;
	ExecProcNodeMtd original_func;  /* Original ExecProcNode, NOT ExecProcNodeReal */

	/* Node lifecycle tracking */
	bool        started;            /* Has NODE_START been emitted? */
	bool        finished;           /* Has NODE_END been emitted? */
	int64       start_time;         /* Timestamp when node started */
	int64       last_call_time;     /* Timestamp of last ExecProcNode call (for early-stop) */
	double      last_progress_tuples; /* Tuple count at last PROGRESS emit */
} WrappedNode;

static WrappedNode wrapped_nodes[MAX_WRAPPED_NODES];
static int num_wrapped_nodes = 0;

/* Per-backend state */
typedef struct TraceState
{
	bool		active;
	int			trace_fd;
	char		trace_path[MAXPGPATH];
	char		trace_id[64];		/* <pid>_<YYYYMMDDHHMMSS> for filenames */
	char		trace_uuid[40];		/* UUID for unique correlation */
	uint64		start_time_ns;		/* Trace start time in nanoseconds */
	uint64		query_id;
	int64		plan_start_time;
	int64		plan_end_time;
	int64		exec_start_time;
	int			nesting_level;
	ParamListInfo bound_params;

	/* Sampling state */
	bool		sampling_active;
	int			sample_count;

	/*
	 * Call stack for tracking current execution context.
	 * This mirrors the actual C call stack - push on every ExecProcNode entry,
	 * pop on every ExecProcNode exit. This ensures SAMPLE events always show
	 * the correct currently-executing node.
	 *
	 * Signal safety: call_stack_depth is written AFTER the array entry, so
	 * signal handler always reads consistent data.
	 */
	volatile int	call_stack_depth;
	Instrumentation *call_stack[MAX_NODE_STACK_DEPTH];

	/* For signal handler - pointer to current planstate root */
	PlanState  *current_planstate;

	/* eBPF tracing state */
	bool		ebpf_active;
	char		ebpf_trace_path[MAXPGPATH];

} TraceState;

static TraceState trace_state = {0};

/* Timeout-based sampling state */
static volatile sig_atomic_t sample_pending = 0;
static TimeoutId pg10046_timeout_id = USER_TIMEOUT;
static bool timeout_registered = false;

/* Forward declarations */
static PlannedStmt *pg10046_planner(Query *parse, const char *query_string,
                                     int cursorOptions, ParamListInfo boundParams);
static void pg10046_ExecutorStart(QueryDesc *queryDesc, int eflags);
static void pg10046_ExecutorRun(QueryDesc *queryDesc, ScanDirection direction,
                                 uint64 count, bool execute_once);
static void pg10046_ExecutorEnd(QueryDesc *queryDesc);
static void open_trace_file(void);
static void write_trace(const char *fmt, ...) pg_attribute_printf(1, 2);
static void write_trace_nonblock(const char *fmt, ...) pg_attribute_printf(1, 2);
static void emit_bind_variables(ParamListInfo params);
static void emit_plan_tree(Plan *plan, int parent_id, int depth, PlannedStmt *pstmt);
static void emit_node_mapping(PlanState *planstate, PlanState *parent, int depth);
static void emit_exec_stats(PlanState *planstate, int parent_id, int depth);
static void emit_node_specific_info(PlanState *planstate, int node_id);
static const char *get_plan_node_name(NodeTag tag);
static const char *get_planstate_node_name(NodeTag tag);
static const char *get_plan_target(Plan *plan, PlannedStmt *pstmt, char *buf, size_t buflen);
static const char *get_scan_target(PlanState *planstate, char *buf, size_t buflen);

/* Sampling functions */
static void setup_sampling_timer(void);
static void cancel_sampling_timer(void);
static void pg10046_timeout_handler(void);
static void process_pending_sample(void);
static Instrumentation *find_running_node(PlanState *planstate);

/* Node wrapping functions */
static void wrap_planstate_nodes(PlanState *planstate);
static void reset_wrapped_nodes(void);
static TupleTableSlot *pg10046_ExecProcNode(PlanState *node);

/*
 * Get timestamp in microseconds from CLOCK_MONOTONIC
 */
static int64
get_trace_timestamp(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

/*
 * Get current wait_event_info from MyProc
 * Returns 0 if not waiting or MyProc is NULL
 */
static uint32
get_current_wait_event(void)
{
	if (MyProc != NULL)
		return MyProc->wait_event_info;
	return 0;
}

/*
 * Decode wait event class from wait_event_info
 */
static const char *
get_wait_event_class_name(uint32 wait_event_info)
{
	uint8 classId = (wait_event_info >> 24) & 0xFF;

	switch (classId)
	{
		case 0x00: return "None";
		case 0x01: return "LWLock";
		case 0x03: return "Lock";
		case 0x04: return "BufferPin";
		case 0x05: return "Activity";
		case 0x06: return "Client";
		case 0x07: return "Extension";
		case 0x08: return "IPC";
		case 0x09: return "Timeout";
		case 0x0A: return "IO";
		default:   return "Unknown";
	}
}

/*
 * Timeout handler - called by PostgreSQL's timeout framework
 *
 * This runs in signal context so we must be careful:
 * - Can read simple memory (wait_event_info, call_stack, Instrumentation are safe)
 * - Can write to file descriptor (write() is async-signal-safe)
 * - Cannot call complex functions or allocate memory
 *
 * SAMPLE format with full stats:
 *   SAMPLE,timestamp,node_ptr,wait_event,sample_num,tuples,blks_hit,blks_read
 */
static void
pg10046_timeout_handler(void)
{
	uint32 wait_event;
	char buf[512];
	int len;
	int64 now;
	struct timespec ts;
	Instrumentation *current_node = NULL;

	/* Stats from current node */
	double tuples = 0;
	int64 blks_hit = 0;
	int64 blks_read = 0;

	if (!trace_state.sampling_active || trace_state.trace_fd <= 0)
		return;

	/* Get timestamp - clock_gettime is signal-safe */
	clock_gettime(CLOCK_MONOTONIC, &ts);
	now = (int64)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;

	/* Read wait event - simple memory read, safe */
	wait_event = 0;
	if (MyProc != NULL)
		wait_event = MyProc->wait_event_info;

	/*
	 * Get current node from call stack - simple memory read, safe.
	 * Read depth first (volatile), then access array. The push operation
	 * writes array entry before incrementing depth, so this is safe.
	 */
	{
		int depth = trace_state.call_stack_depth;
		if (depth > 0 && depth <= MAX_NODE_STACK_DEPTH)
			current_node = trace_state.call_stack[depth - 1];
	}

	/* Read instrumentation stats - simple memory reads, safe */
	if (current_node != NULL)
	{
		tuples = current_node->tuplecount;
		blks_hit = current_node->bufusage.shared_blks_hit;
		blks_read = current_node->bufusage.shared_blks_read;
	}

	trace_state.sample_count++;

	/* Format and write with full stats - snprintf and write are signal-safe */
	len = snprintf(buf, sizeof(buf), "SAMPLE,%ld,%p,0x%08X,%d,%.0f,%ld,%ld\n",
				   now, (void *)current_node, wait_event, trace_state.sample_count,
				   tuples, blks_hit, blks_read);

	if (len > 0 && len < (int)sizeof(buf))
	{
		ssize_t ret pg_attribute_unused();
		ret = write(trace_state.trace_fd, buf, len);
	}

	/* Re-arm timer for next sample */
	if (trace_state.sampling_active && timeout_registered && pg10046_sample_interval_ms > 0)
	{
		enable_timeout_after(pg10046_timeout_id, pg10046_sample_interval_ms);
	}
}

/*
 * Process a pending sample - called from safe context (not signal handler)
 * Also re-arms the timer for the next sample (PG13 doesn't have enable_timeout_every)
 *
 * Captures current node statistics including:
 * - ntuples: tuples processed so far
 * - blks_read: shared blocks read so far
 * - blks_hit: shared buffer hits so far
 *
 * This allows tracking progress through long-running operations like
 * sequential scans on large tables.
 */
static void
process_pending_sample(void)
{
	int64 now;
	uint32 wait_event;
	Instrumentation *current_node;
	const char *wait_class;

	/* Node statistics for progress tracking */
	double ntuples = 0;
	int64 blks_read = 0;
	int64 blks_hit = 0;

	if (!sample_pending || !trace_state.sampling_active)
		return;

	sample_pending = 0;

	now = get_trace_timestamp();
	wait_event = get_current_wait_event();
	wait_class = get_wait_event_class_name(wait_event);

	/* Find currently running node by scanning plan tree */
	current_node = NULL;
	if (trace_state.current_planstate != NULL)
		current_node = find_running_node(trace_state.current_planstate);

	/* Extract node statistics if available */
	if (current_node != NULL)
	{
		ntuples = current_node->ntuples;
		blks_read = current_node->bufusage.shared_blks_read;
		blks_hit = current_node->bufusage.shared_blks_hit;
	}

	/* Only emit sample if we have a wait event or are in a node */
	if (wait_event != 0 || current_node != NULL)
	{
		trace_state.sample_count++;

		/*
		 * SAMPLE format with progress stats:
		 * SAMPLE,timestamp,node_ptr,wait_event_info,wait_class,sample_num,ntuples,blks_read,blks_hit
		 *
		 * This gives visibility into progress during long-running operations
		 */
		write_trace_nonblock("SAMPLE,%ld,%p,0x%08X,%s,%d,%.0f,%ld,%ld\n",
							 now,
							 (void *)current_node,
							 wait_event,
							 wait_class,
							 trace_state.sample_count,
							 ntuples,
							 blks_read,
							 blks_hit);
	}

	/*
	 * Re-arm the timer for next sample.
	 * PG13 doesn't have enable_timeout_every(), so we manually re-enable.
	 * PG16+ could use enable_timeout_every() instead for efficiency.
	 */
	if (trace_state.sampling_active && timeout_registered && pg10046_sample_interval_ms > 0)
	{
		enable_timeout_after(pg10046_timeout_id, pg10046_sample_interval_ms);
	}
}

/*
 * Setup periodic sampling using PostgreSQL's timeout framework
 * This integrates properly with statement_timeout, lock_timeout, etc.
 */
static void
setup_sampling_timer(void)
{
	if (pg10046_sample_interval_ms <= 0)
		return;

	/*
	 * Register timeout lazily on first use.
	 * This avoids issues with shared_preload_libraries where _PG_init
	 * is called in the postmaster before backends exist.
	 */
	if (!timeout_registered)
	{
		RegisterTimeout(USER_TIMEOUT, pg10046_timeout_handler);
		timeout_registered = true;
	}

	trace_state.sampling_active = true;
	trace_state.sample_count = 0;
	sample_pending = 0;

	/* Enable the first timeout - subsequent ones are re-armed in process_pending_sample */
	enable_timeout_after(pg10046_timeout_id, pg10046_sample_interval_ms);

	write_trace("SAMPLING_START,interval_ms=%d\n", pg10046_sample_interval_ms);
}

/*
 * Cancel sampling timer using PostgreSQL's timeout framework
 */
static void
cancel_sampling_timer(void)
{
	if (!trace_state.sampling_active)
		return;

	/* Disable the timeout */
	if (timeout_registered)
	{
		disable_timeout(pg10046_timeout_id, false);
	}

	write_trace("SAMPLING_END,samples=%d\n", trace_state.sample_count);

	trace_state.sampling_active = false;
	sample_pending = 0;
}

/*
 * Push node onto call stack (called on EVERY ExecProcNode entry)
 *
 * Signal safety: Write array entry BEFORE incrementing depth.
 * This ensures the signal handler always sees consistent data.
 */
static void
push_call_stack(Instrumentation *instr)
{
	int depth = trace_state.call_stack_depth;
	if (depth < MAX_NODE_STACK_DEPTH)
	{
		trace_state.call_stack[depth] = instr;
		/* Memory barrier to ensure array write is visible before depth update */
		pg_memory_barrier();
		trace_state.call_stack_depth = depth + 1;
	}
}

/*
 * Pop node from call stack (called on EVERY ExecProcNode exit)
 *
 * Signal safety: Just decrement depth. The old array entry doesn't matter
 * because signal handler checks depth first.
 */
static void
pop_call_stack(void)
{
	if (trace_state.call_stack_depth > 0)
		trace_state.call_stack_depth--;
}

/*
 * Find currently running node by scanning Instrumentation structs
 * Returns the Instrumentation pointer of a node that has running=true
 */
static Instrumentation *
find_running_node(PlanState *planstate)
{
	Instrumentation *result = NULL;

	if (planstate == NULL)
		return NULL;

	/* Check this node */
	if (planstate->instrument && planstate->instrument->running)
		return planstate->instrument;

	/* Check children */
	result = find_running_node(planstate->lefttree);
	if (result)
		return result;

	result = find_running_node(planstate->righttree);
	if (result)
		return result;

	/* Check special node types */
	switch (nodeTag(planstate))
	{
		case T_AppendState:
		{
			AppendState *as = (AppendState *) planstate;
			int i;
			for (i = 0; i < as->as_nplans && !result; i++)
				result = find_running_node(as->appendplans[i]);
			break;
		}
		case T_SubqueryScanState:
		{
			SubqueryScanState *ss = (SubqueryScanState *) planstate;
			result = find_running_node(ss->subplan);
			break;
		}
		default:
			break;
	}

	return result;
}

/*
 * Reset wrapped nodes array - call at start of each query
 */
static void
reset_wrapped_nodes(void)
{
	num_wrapped_nodes = 0;
}

/*
 * Find wrapped node entry for a given PlanState
 * Returns pointer to WrappedNode or NULL if not found
 */
static WrappedNode *
find_wrapped_node(PlanState *node)
{
	int i;
	for (i = 0; i < num_wrapped_nodes; i++)
	{
		if (wrapped_nodes[i].node == node)
			return &wrapped_nodes[i];
	}
	return NULL;
}

/*
 * Emit NODE_END for a specific wrapped node (helper function)
 */
static void
emit_node_end_for_wrapped(WrappedNode *wn, int64 end_time, const char *reason)
{
	PlanState *node;
	Instrumentation *instr;
	const char *node_name;
	char target_buf[NAMEDATALEN];
	const char *target;
	int64 elapsed;

	if (!wn || !wn->started || wn->finished)
		return;

	node = wn->node;
	instr = node ? node->instrument : NULL;
	node_name = node ? get_planstate_node_name(nodeTag(node)) : "Unknown";
	target = node ? get_scan_target(node, target_buf, sizeof(target_buf)) : "";

	elapsed = end_time - wn->start_time;
	wn->finished = true;

	if (instr)
	{
		write_trace("NODE_END,%ld,%p,%s,tuples=%.0f,blks_hit=%ld,blks_read=%ld,time_us=%ld,%s%s%s\n",
					end_time, (void *)instr, node_name,
					instr->tuplecount,
					instr->bufusage.shared_blks_hit,
					instr->bufusage.shared_blks_read,
					elapsed,
					target,
					reason ? ",reason=" : "",
					reason ? reason : "");
	}
	else
	{
		write_trace("NODE_END,%ld,%p,%s,tuples=0,blks_hit=0,blks_read=0,time_us=%ld,%s%s%s\n",
					end_time, (void *)instr, node_name,
					elapsed,
					target,
					reason ? ",reason=" : "",
					reason ? reason : "");
	}
}

/*
 * Cascade NODE_END to all children of a PlanState that started but didn't finish.
 * Called when a parent node returns NULL - all its children are effectively done.
 *
 * Note: Some nodes (like Hash) are called via special paths (MultiExecHash) and
 * may not have started=true. We still need to recurse through them to reach
 * their children (like SeqScan under Hash).
 */
static void
cascade_node_end_to_children(PlanState *parent, int64 end_time)
{
	WrappedNode *wn;
	int i;

	if (parent == NULL)
		return;

	/* Check left child */
	if (parent->lefttree)
	{
		wn = find_wrapped_node(parent->lefttree);
		if (wn && wn->started && !wn->finished)
		{
			emit_node_end_for_wrapped(wn, wn->last_call_time, "PARENT_DONE");
		}
		/* Always recurse - child might have grandchildren that need cascading */
		cascade_node_end_to_children(parent->lefttree, end_time);
	}

	/* Check right child */
	if (parent->righttree)
	{
		wn = find_wrapped_node(parent->righttree);
		if (wn && wn->started && !wn->finished)
		{
			emit_node_end_for_wrapped(wn, wn->last_call_time, "PARENT_DONE");
		}
		/* Always recurse - handles Hash->SeqScan where Hash wasn't tracked */
		cascade_node_end_to_children(parent->righttree, end_time);
	}

	/* Handle special node types with additional children */
	switch (nodeTag(parent))
	{
		case T_AppendState:
		{
			AppendState *as = (AppendState *) parent;
			for (i = 0; i < as->as_nplans; i++)
			{
				wn = find_wrapped_node(as->appendplans[i]);
				if (wn && wn->started && !wn->finished)
					emit_node_end_for_wrapped(wn, wn->last_call_time, "PARENT_DONE");
				cascade_node_end_to_children(as->appendplans[i], end_time);
			}
			break;
		}
		case T_MergeAppendState:
		{
			MergeAppendState *ms = (MergeAppendState *) parent;
			for (i = 0; i < ms->ms_nplans; i++)
			{
				wn = find_wrapped_node(ms->mergeplans[i]);
				if (wn && wn->started && !wn->finished)
					emit_node_end_for_wrapped(wn, wn->last_call_time, "PARENT_DONE");
				cascade_node_end_to_children(ms->mergeplans[i], end_time);
			}
			break;
		}
		case T_SubqueryScanState:
		{
			SubqueryScanState *ss = (SubqueryScanState *) parent;
			wn = find_wrapped_node(ss->subplan);
			if (wn && wn->started && !wn->finished)
				emit_node_end_for_wrapped(wn, wn->last_call_time, "PARENT_DONE");
			cascade_node_end_to_children(ss->subplan, end_time);
			break;
		}
		case T_BitmapAndState:
		{
			BitmapAndState *bas = (BitmapAndState *) parent;
			for (i = 0; i < bas->nplans; i++)
			{
				wn = find_wrapped_node(bas->bitmapplans[i]);
				if (wn && wn->started && !wn->finished)
					emit_node_end_for_wrapped(wn, wn->last_call_time, "PARENT_DONE");
				cascade_node_end_to_children(bas->bitmapplans[i], end_time);
			}
			break;
		}
		case T_BitmapOrState:
		{
			BitmapOrState *bos = (BitmapOrState *) parent;
			for (i = 0; i < bos->nplans; i++)
			{
				wn = find_wrapped_node(bos->bitmapplans[i]);
				if (wn && wn->started && !wn->finished)
					emit_node_end_for_wrapped(wn, wn->last_call_time, "PARENT_DONE");
				cascade_node_end_to_children(bos->bitmapplans[i], end_time);
			}
			break;
		}
		default:
			break;
	}
}

/*
 * Our ExecProcNode wrapper - tracks node lifecycle and call stack
 *
 * Call stack tracking (Alternative 3):
 * - Push onto call_stack on EVERY entry (mirrors C call stack)
 * - Pop from call_stack on EVERY exit
 * - SAMPLE handler reads top of stack for accurate "currently executing" node
 *
 * Lifecycle events (for report):
 * - NODE_START: When node is first called (scan begins)
 * - PROGRESS: Every Y tuples if pg_10046.progress_interval_tuples > 0 (debug mode)
 * - NODE_END: When node returns NULL, cascades to children
 *
 * IMPORTANT: PostgreSQL's ExecProcNodeFirst replaces ExecProcNode after
 * the first call. We must re-wrap after calling the original.
 */
static TupleTableSlot *
pg10046_ExecProcNode(PlanState *node)
{
	TupleTableSlot *result;
	WrappedNode *wn;
	Instrumentation *instr = node->instrument;
	const char *node_name = get_planstate_node_name(nodeTag(node));
	char target_buf[NAMEDATALEN];
	const char *target;
	int64 now;
	double current_tuples;

	/* Find our wrapped node entry */
	wn = find_wrapped_node(node);
	if (wn == NULL)
	{
		elog(ERROR, "pg_10046: could not find wrapped node for %p", node);
		return NULL;
	}

	/* Track last call time for accurate NODE_END on early stop (LIMIT, etc.) */
	now = get_trace_timestamp();
	wn->last_call_time = now;

	/* Get scan target (table/index name) for context */
	target = get_scan_target(node, target_buf, sizeof(target_buf));

	/*
	 * NODE_START: Emit on first call to this node (lifecycle event)
	 */
	if (!wn->started)
	{
		wn->started = true;
		wn->start_time = now;
		wn->last_progress_tuples = 0;

		write_trace("NODE_START,%ld,%p,%s,%s\n",
					now, (void *)instr, node_name, target);
	}

	/*
	 * PUSH onto call stack (on EVERY entry)
	 * This is the key to Alternative 3 - stack mirrors C call stack
	 */
	push_call_stack(instr);

	/* Call original ExecProcNode */
	result = wn->original_func(node);

	/*
	 * CRITICAL: PostgreSQL's ExecProcNodeFirst replaces node->ExecProcNode
	 * after the first call. If that happened, we need to:
	 * 1. Update our stored original to the new function
	 * 2. Re-install our wrapper
	 */
	if (node->ExecProcNode != pg10046_ExecProcNode)
	{
		wn->original_func = node->ExecProcNode;
		node->ExecProcNode = pg10046_ExecProcNode;
	}

	/*
	 * POP from call stack (on EVERY exit)
	 */
	pop_call_stack();

	/* Get current tuple count */
	current_tuples = instr ? instr->tuplecount : 0;

	/*
	 * PROGRESS: Emit every Y tuples (debug mode)
	 */
	if (pg10046_progress_interval_tuples > 0 && instr && !TupIsNull(result))
	{
		double tuples_since_last = current_tuples - wn->last_progress_tuples;

		if (tuples_since_last >= pg10046_progress_interval_tuples)
		{
			now = get_trace_timestamp();
			write_trace("PROGRESS,%ld,%p,%s,%.0f,%ld,%ld\n",
						now, (void *)instr, node_name,
						current_tuples,
						instr->bufusage.shared_blks_hit,
						instr->bufusage.shared_blks_read);

			wn->last_progress_tuples = current_tuples;
		}
	}

	/*
	 * NODE_END: Emit when node returns NULL or empty slot (no more tuples)
	 * Also cascade to any children that started but didn't finish naturally
	 *
	 * NOTE: PostgreSQL uses TupIsNull() to check for end-of-data, which is:
	 *   (slot == NULL) || (slot->tts_isempty)
	 * Many scan nodes return an empty slot rather than NULL pointer.
	 */
	if (TupIsNull(result) && !wn->finished)
	{
		int64 elapsed;

		wn->finished = true;
		now = get_trace_timestamp();
		elapsed = now - wn->start_time;

		/*
		 * First, cascade NODE_END to any unfinished children.
		 * This ensures children appear before parent in trace (correct order).
		 */
		cascade_node_end_to_children(node, now);

		/* Emit NODE_END for this node */
		if (instr)
		{
			write_trace("NODE_END,%ld,%p,%s,tuples=%.0f,blks_hit=%ld,blks_read=%ld,time_us=%ld,%s\n",
						now, (void *)instr, node_name,
						current_tuples,
						instr->bufusage.shared_blks_hit,
						instr->bufusage.shared_blks_read,
						elapsed,
						target);
		}
		else
		{
			write_trace("NODE_END,%ld,%p,%s,tuples=0,blks_hit=0,blks_read=0,time_us=%ld,%s\n",
						now, (void *)instr, node_name, elapsed, target);
		}
	}

	return result;
}

/*
 * Wrap all PlanState nodes to use our ExecProcNode wrapper
 *
 * This saves the original ExecProcNode pointer and replaces it with ours.
 * We DON'T touch ExecProcNodeReal - that's for PostgreSQL's use.
 */
static void
wrap_planstate_nodes(PlanState *planstate)
{
	if (planstate == NULL)
		return;

	/* Only wrap if not already wrapped and we have room */
	if (planstate->ExecProcNode != NULL &&
		planstate->ExecProcNode != pg10046_ExecProcNode &&
		num_wrapped_nodes < MAX_WRAPPED_NODES)
	{
		/* Save original in our array (NOT in ExecProcNodeReal!) */
		wrapped_nodes[num_wrapped_nodes].node = planstate;
		wrapped_nodes[num_wrapped_nodes].original_func = planstate->ExecProcNode;

		/* Initialize lifecycle tracking */
		wrapped_nodes[num_wrapped_nodes].started = false;
		wrapped_nodes[num_wrapped_nodes].finished = false;
		wrapped_nodes[num_wrapped_nodes].start_time = 0;
		wrapped_nodes[num_wrapped_nodes].last_call_time = 0;
		wrapped_nodes[num_wrapped_nodes].last_progress_tuples = 0;

		num_wrapped_nodes++;

		/* Install our wrapper */
		planstate->ExecProcNode = pg10046_ExecProcNode;
	}

	/* Recurse to children */
	wrap_planstate_nodes(planstate->lefttree);
	wrap_planstate_nodes(planstate->righttree);

	/* Handle special node types with additional children */
	switch (nodeTag(planstate))
	{
		case T_AppendState:
		{
			AppendState *as = (AppendState *) planstate;
			int i;
			for (i = 0; i < as->as_nplans; i++)
				wrap_planstate_nodes(as->appendplans[i]);
			break;
		}

		case T_MergeAppendState:
		{
			MergeAppendState *ms = (MergeAppendState *) planstate;
			int i;
			for (i = 0; i < ms->ms_nplans; i++)
				wrap_planstate_nodes(ms->mergeplans[i]);
			break;
		}

		case T_SubqueryScanState:
		{
			SubqueryScanState *ss = (SubqueryScanState *) planstate;
			wrap_planstate_nodes(ss->subplan);
			break;
		}

		case T_BitmapAndState:
		{
			BitmapAndState *bas = (BitmapAndState *) planstate;
			int i;
			for (i = 0; i < bas->nplans; i++)
				wrap_planstate_nodes(bas->bitmapplans[i]);
			break;
		}

		case T_BitmapOrState:
		{
			BitmapOrState *bos = (BitmapOrState *) planstate;
			int i;
			for (i = 0; i < bos->nplans; i++)
				wrap_planstate_nodes(bos->bitmapplans[i]);
			break;
		}

		default:
			break;
	}
}

/*
 * Module load callback
 */
void
_PG_init(void)
{
	DefineCustomBoolVariable("pg_10046.enabled",
							 "Enable SQL tracing",
							 NULL,
							 &pg10046_enabled,
							 false,
							 PGC_USERSET,
							 0,
							 NULL, NULL, NULL);

	DefineCustomStringVariable("pg_10046.trace_dir",
							   "Directory for trace files",
							   NULL,
							   &pg10046_trace_dir,
							   "/tmp",
							   PGC_USERSET,
							   0,
							   NULL, NULL, NULL);

	DefineCustomIntVariable("pg_10046.sample_interval_ms",
							"Sampling interval in milliseconds",
							"How often to sample wait_event_info during execution",
							&pg10046_sample_interval_ms,
							10,     /* default 10ms */
							0,      /* min (0 = disabled) */
							1000,   /* max 1 second */
							PGC_USERSET,
							GUC_UNIT_MS,
							NULL, NULL, NULL);

	DefineCustomIntVariable("pg_10046.progress_interval_tuples",
							"Debug: emit PROGRESS every N tuples",
							"Set to 0 to disable tuple-based progress reporting (default). "
							"Set to e.g. 1000 to emit PROGRESS events every 1000 tuples.",
							&pg10046_progress_interval_tuples,
							0,      /* default: disabled */
							0,      /* min (0 = disabled) */
							1000000, /* max 1M tuples */
							PGC_USERSET,
							0,
							NULL, NULL, NULL);

	DefineCustomBoolVariable("pg_10046.ebpf_enabled",
							 "Enable eBPF IO tracing via pg_10046d daemon",
							 "When enabled, extension automatically starts/stops eBPF "
							 "IO tracing through the pg_10046d daemon.",
							 &pg10046_ebpf_enabled,
							 false,
							 PGC_USERSET,
							 0,
							 NULL, NULL, NULL);

	DefineCustomStringVariable("pg_10046.daemon_socket",
							   "Unix socket path for pg_10046d daemon",
							   NULL,
							   &pg10046_daemon_socket,
							   DEFAULT_DAEMON_SOCKET,
							   PGC_USERSET,
							   0,
							   NULL, NULL, NULL);

	/*
	 * NOTE: Timeout registration is done lazily in setup_sampling_timer()
	 * to avoid issues with shared_preload_libraries context.
	 */

	/* Install hooks */
	prev_planner_hook = planner_hook;
	planner_hook = pg10046_planner;

	prev_ExecutorStart = ExecutorStart_hook;
	ExecutorStart_hook = pg10046_ExecutorStart;

	prev_ExecutorRun = ExecutorRun_hook;
	ExecutorRun_hook = pg10046_ExecutorRun;

	prev_ExecutorEnd = ExecutorEnd_hook;
	ExecutorEnd_hook = pg10046_ExecutorEnd;

#if PG_VERSION_NUM >= 150000
	MarkGUCPrefixReserved("pg_10046");
#endif
}

/*
 * Module unload callback
 */
void
_PG_fini(void)
{
	/* Cancel any active sampling using PostgreSQL's timeout framework */
	if (trace_state.sampling_active && timeout_registered)
	{
		disable_timeout(pg10046_timeout_id, false);
		trace_state.sampling_active = false;
	}

	/* Stop eBPF tracing if active */
	if (trace_state.ebpf_active)
	{
		stop_ebpf_trace();
	}

	/* Close trace file */
	if (trace_state.trace_fd > 0)
	{
		close(trace_state.trace_fd);
		trace_state.trace_fd = 0;
	}

	/* Restore hooks */
	planner_hook = prev_planner_hook;
	ExecutorStart_hook = prev_ExecutorStart;
	ExecutorRun_hook = prev_ExecutorRun;
	ExecutorEnd_hook = prev_ExecutorEnd;
}

/*
 * Send command to pg_10046d daemon and get response
 * Returns true on success, false on error
 * Response is stored in response_buf (must be at least 256 bytes)
 */
static bool
ebpf_daemon_command(const char *cmd, char *response_buf, size_t response_len)
{
	int sock;
	struct sockaddr_un addr;
	const char *socket_path;
	ssize_t n;

	socket_path = pg10046_daemon_socket ? pg10046_daemon_socket : DEFAULT_DAEMON_SOCKET;

	/* Create Unix socket */
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
	{
		elog(DEBUG1, "pg_10046: socket() failed: %m");
		return false;
	}

	/* Connect to daemon */
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		elog(DEBUG1, "pg_10046: connect to %s failed: %m", socket_path);
		close(sock);
		return false;
	}

	/* Send command */
	if (write(sock, cmd, strlen(cmd)) < 0)
	{
		elog(DEBUG1, "pg_10046: write failed: %m");
		close(sock);
		return false;
	}

	/* Read response */
	n = read(sock, response_buf, response_len - 1);
	if (n < 0)
	{
		elog(DEBUG1, "pg_10046: read failed: %m");
		close(sock);
		return false;
	}
	response_buf[n] = '\0';

	close(sock);
	return true;
}

/*
 * Start eBPF IO tracing via daemon
 */
static void
start_ebpf_trace(void)
{
	char cmd[256];
	char response[256];

	if (trace_state.ebpf_active)
		return;

	snprintf(cmd, sizeof(cmd), "START %d %s",
			 MyProcPid, trace_state.trace_uuid);

	if (ebpf_daemon_command(cmd, response, sizeof(response)))
	{
		if (strncmp(response, "OK ", 3) == 0)
		{
			trace_state.ebpf_active = true;
			strncpy(trace_state.ebpf_trace_path, response + 3,
					sizeof(trace_state.ebpf_trace_path) - 1);
			trace_state.ebpf_trace_path[sizeof(trace_state.ebpf_trace_path) - 1] = '\0';

			/* Log to extension trace */
			write_trace("# EBPF_START: %s\n", trace_state.ebpf_trace_path);

			elog(DEBUG1, "pg_10046: eBPF tracing started: %s", trace_state.ebpf_trace_path);
		}
		else
		{
			elog(WARNING, "pg_10046: eBPF daemon error: %s", response);
		}
	}
	else
	{
		elog(DEBUG1, "pg_10046: Could not connect to eBPF daemon");
	}
}

/*
 * Stop eBPF IO tracing via daemon
 */
static void
stop_ebpf_trace(void)
{
	char cmd[64];
	char response[256];

	if (!trace_state.ebpf_active)
		return;

	snprintf(cmd, sizeof(cmd), "STOP %d", MyProcPid);

	if (ebpf_daemon_command(cmd, response, sizeof(response)))
	{
		if (strncmp(response, "OK ", 3) == 0)
		{
			/* Log to extension trace */
			write_trace("# EBPF_STOP: %s\n", response + 3);
			elog(DEBUG1, "pg_10046: eBPF tracing stopped: %s", response + 3);
		}
	}

	trace_state.ebpf_active = false;
	trace_state.ebpf_trace_path[0] = '\0';
}

/*
 * Generate a simple UUID v4 (random-based)
 * Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
 */
static void
generate_uuid(char *buf, size_t buflen)
{
	static bool seeded = false;
	uint32 r1, r2, r3, r4;

	if (!seeded)
	{
		struct timespec ts;
		clock_gettime(CLOCK_REALTIME, &ts);
		srand((unsigned int)(ts.tv_nsec ^ ts.tv_sec ^ MyProcPid));
		seeded = true;
	}

	r1 = (uint32) rand();
	r2 = (uint32) rand();
	r3 = (uint32) rand();
	r4 = (uint32) rand();

	/* Format as UUID v4: set version (4) and variant bits */
	snprintf(buf, buflen,
			 "%08x-%04x-4%03x-%x%03x-%04x%08x",
			 r1,
			 (r2 >> 16) & 0xFFFF,
			 r2 & 0x0FFF,
			 8 + (rand() % 4),  /* variant: 8, 9, a, or b */
			 r3 & 0x0FFF,
			 (r3 >> 12) & 0xFFFF,
			 r4);
}

/*
 * Open trace file for current backend
 *
 * File naming: pg_10046_<trace_id>.trc
 * Where trace_id = <pid>_<YYYYMMDDHHMMSS>
 *
 * Header includes:
 * - TRACE_ID: human-readable identifier for filenames
 * - TRACE_UUID: unique identifier for programmatic correlation
 */
static void
open_trace_file(void)
{
	struct timespec ts;
	time_t now;
	struct tm *tm_info;
	char timestamp[20];

	if (trace_state.trace_fd > 0)
		return;

	clock_gettime(CLOCK_REALTIME, &ts);
	now = time(NULL);
	tm_info = localtime(&now);

	/* Generate timestamp as YYYYMMDDHHMMSS */
	strftime(timestamp, sizeof(timestamp), "%Y%m%d%H%M%S", tm_info);

	/* Generate TRACE_ID: <pid>_<timestamp> */
	snprintf(trace_state.trace_id, sizeof(trace_state.trace_id),
			 "%d_%s", MyProcPid, timestamp);

	/* Generate UUID for unique correlation */
	generate_uuid(trace_state.trace_uuid, sizeof(trace_state.trace_uuid));

	/* Store start time in nanoseconds */
	trace_state.start_time_ns = (uint64) ts.tv_sec * 1000000000ULL + ts.tv_nsec;

	/* File naming: pg_10046_<trace_id>.trc */
	snprintf(trace_state.trace_path, MAXPGPATH,
			 "%s/pg_10046_%s.trc",
			 pg10046_trace_dir ? pg10046_trace_dir : "/tmp",
			 trace_state.trace_id);

	trace_state.trace_fd = open(trace_state.trace_path,
								O_WRONLY | O_CREAT | O_TRUNC,
								S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	if (trace_state.trace_fd < 0)
	{
		ereport(WARNING,
				(errcode_for_file_access(),
				 errmsg("pg_10046: could not open trace file \"%s\": %m",
						trace_state.trace_path)));
		return;
	}

	trace_state.active = true;
	trace_state.query_id = 0;
	trace_state.call_stack_depth = 0;

	/* Write trace header */
	write_trace("# PG_10046 TRACE\n");
	write_trace("# TRACE_ID: %s\n", trace_state.trace_id);
	write_trace("# TRACE_UUID: %s\n", trace_state.trace_uuid);
	write_trace("# PID: %d\n", MyProcPid);
	write_trace("# START_TIME: %lu\n", (unsigned long) trace_state.start_time_ns);
	write_trace("# SAMPLE_INTERVAL_MS: %d\n", pg10046_sample_interval_ms);
	write_trace("# EBPF_ENABLED: %s\n", pg10046_ebpf_enabled ? "true" : "false");
	write_trace("#\n");

	/* Start eBPF tracing if enabled */
	if (pg10046_ebpf_enabled)
	{
		start_ebpf_trace();
	}
	else
	{
		write_trace("# To collect IO events manually, start eBPF tracer:\n");
		write_trace("#   pg_10046_ebpf.sh start %d %s\n", MyProcPid, trace_state.trace_uuid);
		write_trace("# eBPF trace file: pg_10046_io_%s.trc\n", trace_state.trace_id);
		write_trace("#\n");
	}
}

/*
 * Write formatted line to trace file
 */
static void
write_trace(const char *fmt, ...)
{
	va_list		args;
	char		buf[8192];
	int			len;

	if (trace_state.trace_fd <= 0)
		return;

	va_start(args, fmt);
	len = vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	if (len > 0)
	{
		ssize_t ret pg_attribute_unused();
		ret = write(trace_state.trace_fd, buf, Min(len, (int)sizeof(buf) - 1));
	}
}

/*
 * Write trace without blocking (for use in/near signal context)
 * Uses smaller buffer and non-blocking semantics
 */
static void
write_trace_nonblock(const char *fmt, ...)
{
	va_list		args;
	char		buf[512];
	int			len;

	if (trace_state.trace_fd <= 0)
		return;

	va_start(args, fmt);
	len = vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	if (len > 0)
	{
		/* Non-blocking write - ignore errors */
		ssize_t ret pg_attribute_unused();
		ret = write(trace_state.trace_fd, buf, Min(len, (int)sizeof(buf) - 1));
	}
}

/*
 * Get node type name from Plan NodeTag
 */
static const char *
get_plan_node_name(NodeTag tag)
{
	switch (tag)
	{
		/* Scan nodes */
		case T_SeqScan:                 return "SeqScan";
		case T_SampleScan:              return "SampleScan";
		case T_IndexScan:               return "IndexScan";
		case T_IndexOnlyScan:           return "IndexOnlyScan";
		case T_BitmapIndexScan:         return "BitmapIndexScan";
		case T_BitmapHeapScan:          return "BitmapHeapScan";
		case T_TidScan:                 return "TidScan";
		case T_SubqueryScan:            return "SubqueryScan";
		case T_FunctionScan:            return "FunctionScan";
		case T_ValuesScan:              return "ValuesScan";
		case T_TableFuncScan:           return "TableFuncScan";
		case T_CteScan:                 return "CteScan";
		case T_NamedTuplestoreScan:     return "NamedTuplestoreScan";
		case T_WorkTableScan:           return "WorkTableScan";
		case T_ForeignScan:             return "ForeignScan";
		case T_CustomScan:              return "CustomScan";

		/* Join nodes */
		case T_NestLoop:                return "NestLoop";
		case T_MergeJoin:               return "MergeJoin";
		case T_HashJoin:                return "HashJoin";

		/* Materialization nodes */
		case T_Material:                return "Material";
		case T_Sort:                    return "Sort";
		case T_IncrementalSort:         return "IncrementalSort";
		case T_Group:                   return "Group";
		case T_Agg:                     return "Aggregate";
		case T_WindowAgg:               return "WindowAgg";
		case T_Unique:                  return "Unique";
		case T_Gather:                  return "Gather";
		case T_GatherMerge:             return "GatherMerge";
		case T_Hash:                    return "Hash";
		case T_SetOp:                   return "SetOp";
		case T_LockRows:                return "LockRows";
		case T_Limit:                   return "Limit";

		/* Other nodes */
		case T_Result:                  return "Result";
		case T_ProjectSet:              return "ProjectSet";
		case T_ModifyTable:             return "ModifyTable";
		case T_Append:                  return "Append";
		case T_MergeAppend:             return "MergeAppend";
		case T_RecursiveUnion:          return "RecursiveUnion";
		case T_BitmapAnd:               return "BitmapAnd";
		case T_BitmapOr:                return "BitmapOr";

		default:                        return "Unknown";
	}
}

/*
 * Get node type name from PlanState NodeTag
 */
static const char *
get_planstate_node_name(NodeTag tag)
{
	switch (tag)
	{
		/* Scan nodes */
		case T_SeqScanState:            return "SeqScan";
		case T_SampleScanState:         return "SampleScan";
		case T_IndexScanState:          return "IndexScan";
		case T_IndexOnlyScanState:      return "IndexOnlyScan";
		case T_BitmapIndexScanState:    return "BitmapIndexScan";
		case T_BitmapHeapScanState:     return "BitmapHeapScan";
		case T_TidScanState:            return "TidScan";
		case T_SubqueryScanState:       return "SubqueryScan";
		case T_FunctionScanState:       return "FunctionScan";
		case T_ValuesScanState:         return "ValuesScan";
		case T_TableFuncScanState:      return "TableFuncScan";
		case T_CteScanState:            return "CteScan";
		case T_NamedTuplestoreScanState: return "NamedTuplestoreScan";
		case T_WorkTableScanState:      return "WorkTableScan";
		case T_ForeignScanState:        return "ForeignScan";
		case T_CustomScanState:         return "CustomScan";

		/* Join nodes */
		case T_NestLoopState:           return "NestLoop";
		case T_MergeJoinState:          return "MergeJoin";
		case T_HashJoinState:           return "HashJoin";

		/* Materialization nodes */
		case T_MaterialState:           return "Material";
		case T_SortState:               return "Sort";
		case T_GroupState:              return "Group";
		case T_AggState:                return "Aggregate";
		case T_WindowAggState:          return "WindowAgg";
		case T_UniqueState:             return "Unique";
		case T_GatherState:             return "Gather";
		case T_GatherMergeState:        return "GatherMerge";
		case T_HashState:               return "Hash";
		case T_SetOpState:              return "SetOp";
		case T_LockRowsState:           return "LockRows";
		case T_LimitState:              return "Limit";

		/* Other nodes */
		case T_ResultState:             return "Result";
		case T_ProjectSetState:         return "ProjectSet";
		case T_ModifyTableState:        return "ModifyTable";
		case T_AppendState:             return "Append";
		case T_MergeAppendState:        return "MergeAppend";
		case T_RecursiveUnionState:     return "RecursiveUnion";
		case T_BitmapAndState:          return "BitmapAnd";
		case T_BitmapOrState:           return "BitmapOr";

		default:                        return "Unknown";
	}
}

/*
 * Get scan target from Plan node
 * For IndexScan/IndexOnlyScan: returns "index_name on table_name"
 * For other scans: returns "table_name"
 */
static const char *
get_plan_target(Plan *plan, PlannedStmt *pstmt, char *buf, size_t buflen)
{
	Oid relid = InvalidOid;
	Oid indexid = InvalidOid;

	switch (nodeTag(plan))
	{
		case T_IndexScan:
		{
			IndexScan *iscan = (IndexScan *) plan;
			Scan *scan = (Scan *) plan;
			RangeTblEntry *rte;

			indexid = iscan->indexid;
			if (pstmt->rtable &&
				scan->scanrelid > 0 &&
				scan->scanrelid <= list_length(pstmt->rtable))
			{
				rte = rt_fetch(scan->scanrelid, pstmt->rtable);
				relid = rte->relid;
			}
			break;
		}
		case T_IndexOnlyScan:
		{
			IndexOnlyScan *ioscan = (IndexOnlyScan *) plan;
			Scan *scan = (Scan *) plan;
			RangeTblEntry *rte;

			indexid = ioscan->indexid;
			if (pstmt->rtable &&
				scan->scanrelid > 0 &&
				scan->scanrelid <= list_length(pstmt->rtable))
			{
				rte = rt_fetch(scan->scanrelid, pstmt->rtable);
				relid = rte->relid;
			}
			break;
		}
		case T_BitmapIndexScan:
		{
			BitmapIndexScan *biscan = (BitmapIndexScan *) plan;
			indexid = biscan->indexid;
			break;
		}
		case T_SeqScan:
		case T_SampleScan:
		case T_BitmapHeapScan:
		case T_TidScan:
		{
			Scan *scan = (Scan *) plan;
			RangeTblEntry *rte;

			if (pstmt->rtable &&
				scan->scanrelid > 0 &&
				scan->scanrelid <= list_length(pstmt->rtable))
			{
				rte = rt_fetch(scan->scanrelid, pstmt->rtable);
				relid = rte->relid;
			}
			break;
		}
		default:
			break;
	}

	/* Format output: "index on table" or just "table" */
	if (OidIsValid(indexid) && OidIsValid(relid))
	{
		char *indexname = get_rel_name(indexid);
		char *relname = get_rel_name(relid);
		if (indexname && relname)
		{
			snprintf(buf, buflen, "%s on %s", indexname, relname);
			pfree(indexname);
			pfree(relname);
			return buf;
		}
		if (indexname) pfree(indexname);
		if (relname) pfree(relname);
	}
	else if (OidIsValid(indexid))
	{
		char *indexname = get_rel_name(indexid);
		if (indexname)
		{
			snprintf(buf, buflen, "%s", indexname);
			pfree(indexname);
			return buf;
		}
	}
	else if (OidIsValid(relid))
	{
		char *relname = get_rel_name(relid);
		if (relname)
		{
			snprintf(buf, buflen, "%s", relname);
			pfree(relname);
			return buf;
		}
	}

	buf[0] = '\0';
	return buf;
}

/*
 * Get scan target from PlanState node
 * For IndexScan/IndexOnlyScan: returns "index_name on table_name"
 * For other scans: returns "table_name"
 */
static const char *
get_scan_target(PlanState *planstate, char *buf, size_t buflen)
{
	Plan *plan = planstate->plan;
	Oid relid = InvalidOid;
	Oid indexid = InvalidOid;

	switch (nodeTag(plan))
	{
		case T_IndexScan:
		{
			IndexScan *iscan = (IndexScan *) plan;
			Scan *scan = (Scan *) plan;
			RangeTblEntry *rte;

			indexid = iscan->indexid;
			if (planstate->state &&
				planstate->state->es_range_table &&
				scan->scanrelid > 0 &&
				scan->scanrelid <= list_length(planstate->state->es_range_table))
			{
				rte = rt_fetch(scan->scanrelid, planstate->state->es_range_table);
				relid = rte->relid;
			}
			break;
		}
		case T_IndexOnlyScan:
		{
			IndexOnlyScan *ioscan = (IndexOnlyScan *) plan;
			Scan *scan = (Scan *) plan;
			RangeTblEntry *rte;

			indexid = ioscan->indexid;
			if (planstate->state &&
				planstate->state->es_range_table &&
				scan->scanrelid > 0 &&
				scan->scanrelid <= list_length(planstate->state->es_range_table))
			{
				rte = rt_fetch(scan->scanrelid, planstate->state->es_range_table);
				relid = rte->relid;
			}
			break;
		}
		case T_BitmapIndexScan:
		{
			BitmapIndexScan *biscan = (BitmapIndexScan *) plan;
			indexid = biscan->indexid;
			break;
		}
		case T_SeqScan:
		case T_SampleScan:
		case T_BitmapHeapScan:
		case T_TidScan:
		{
			Scan *scan = (Scan *) plan;
			RangeTblEntry *rte;

			if (planstate->state &&
				planstate->state->es_range_table &&
				scan->scanrelid > 0 &&
				scan->scanrelid <= list_length(planstate->state->es_range_table))
			{
				rte = rt_fetch(scan->scanrelid, planstate->state->es_range_table);
				relid = rte->relid;
			}
			break;
		}
		default:
			break;
	}

	/* Format output: "index on table" or just "table" */
	if (OidIsValid(indexid) && OidIsValid(relid))
	{
		char *indexname = get_rel_name(indexid);
		char *relname = get_rel_name(relid);
		if (indexname && relname)
		{
			snprintf(buf, buflen, "%s on %s", indexname, relname);
			pfree(indexname);
			pfree(relname);
			return buf;
		}
		if (indexname) pfree(indexname);
		if (relname) pfree(relname);
	}
	else if (OidIsValid(indexid))
	{
		char *indexname = get_rel_name(indexid);
		if (indexname)
		{
			snprintf(buf, buflen, "%s", indexname);
			pfree(indexname);
			return buf;
		}
	}
	else if (OidIsValid(relid))
	{
		char *relname = get_rel_name(relid);
		if (relname)
		{
			snprintf(buf, buflen, "%s", relname);
			pfree(relname);
			return buf;
		}
	}

	buf[0] = '\0';
	return buf;
}

/*
 * Emit bind variable values
 * Format: BIND,index,type_name,value
 */
static void
emit_bind_variables(ParamListInfo params)
{
	int i;

	if (params == NULL || params->numParams == 0)
		return;

	write_trace("BINDS_START,%d\n", params->numParams);

	for (i = 0; i < params->numParams; i++)
	{
		ParamExternData *param;
		ParamExternData pdata;
		Oid typoid;
		bool isnull;
		Datum value;
		char *type_name;
		char *value_str;

		/* Get parameter data - handle both old and new style */
		if (params->paramFetch != NULL)
		{
			/* New style: fetch parameter on demand */
			param = params->paramFetch(params, i + 1, false, &pdata);
		}
		else
		{
			/* Old style: direct access */
			param = &params->params[i];
		}

		if (param == NULL)
		{
			write_trace("BIND,%d,unknown,NULL\n", i + 1);
			continue;
		}

		typoid = param->ptype;
		isnull = param->isnull;
		value = param->value;

		/* Get type name */
		if (OidIsValid(typoid))
			type_name = format_type_be(typoid);
		else
			type_name = pstrdup("unknown");

		/* Convert value to string */
		if (isnull)
		{
			value_str = "NULL";
		}
		else if (OidIsValid(typoid))
		{
			Oid typoutput;
			bool typIsVarlena;

			getTypeOutputInfo(typoid, &typoutput, &typIsVarlena);
			value_str = OidOutputFunctionCall(typoutput, value);

			/* Truncate long values */
			if (strlen(value_str) > 100)
			{
				value_str[97] = '.';
				value_str[98] = '.';
				value_str[99] = '.';
				value_str[100] = '\0';
			}
		}
		else
		{
			value_str = "(unknown type)";
		}

		write_trace("BIND,%d,%s,%s\n", i + 1, type_name, value_str);

		if (OidIsValid(typoid))
			pfree(type_name);
	}

	write_trace("BINDS_END\n");
}

/* Global node ID counter for tree reconstruction */
static int plan_node_id_counter = 0;

/*
 * Emit plan tree structure immediately after planning
 * Format: PLAN,node_id,parent_id,depth,node_type,est_rows,est_cost,target
 */
static void
emit_plan_tree(Plan *plan, int parent_id, int depth, PlannedStmt *pstmt)
{
	const char *node_type;
	char target_buf[NAMEDATALEN];
	const char *target;
	ListCell *lc;
	int my_id;

	if (plan == NULL)
		return;

	my_id = ++plan_node_id_counter;
	node_type = get_plan_node_name(nodeTag(plan));
	target = get_plan_target(plan, pstmt, target_buf, sizeof(target_buf));

	/* Emit PLAN line with ID, parent ID for tree reconstruction */
	write_trace("PLAN,%d,%d,%d,%s,%.0f,%.2f,%s\n",
				my_id,
				parent_id,
				depth,
				node_type,
				plan->plan_rows,
				plan->total_cost,
				target);

	/* Recurse to children with my_id as their parent */
	emit_plan_tree(outerPlan(plan), my_id, depth + 1, pstmt);
	emit_plan_tree(innerPlan(plan), my_id, depth + 1, pstmt);

	/* Handle special node types with additional children */
	switch (nodeTag(plan))
	{
		case T_Append:
		{
			Append *ap = (Append *) plan;
			foreach(lc, ap->appendplans)
				emit_plan_tree((Plan *) lfirst(lc), my_id, depth + 1, pstmt);
			break;
		}

		case T_MergeAppend:
		{
			MergeAppend *ma = (MergeAppend *) plan;
			foreach(lc, ma->mergeplans)
				emit_plan_tree((Plan *) lfirst(lc), my_id, depth + 1, pstmt);
			break;
		}

		case T_SubqueryScan:
		{
			SubqueryScan *ss = (SubqueryScan *) plan;
			emit_plan_tree(ss->subplan, my_id, depth + 1, pstmt);
			break;
		}

		case T_BitmapAnd:
		{
			BitmapAnd *ba = (BitmapAnd *) plan;
			foreach(lc, ba->bitmapplans)
				emit_plan_tree((Plan *) lfirst(lc), my_id, depth + 1, pstmt);
			break;
		}

		case T_BitmapOr:
		{
			BitmapOr *bo = (BitmapOr *) plan;
			foreach(lc, bo->bitmapplans)
				emit_plan_tree((Plan *) lfirst(lc), my_id, depth + 1, pstmt);
			break;
		}

		default:
			break;
	}
}

/*
 * Recursively emit node mapping for the plan tree
 * Format: NODE_MAP,instr_ptr,parent_instr_ptr,node_type,depth,target
 */
static void
emit_node_mapping(PlanState *planstate, PlanState *parent, int depth)
{
	const char *node_type;
	char target_buf[NAMEDATALEN];
	const char *target;

	if (planstate == NULL)
		return;

	node_type = get_planstate_node_name(nodeTag(planstate));
	target = get_scan_target(planstate, target_buf, sizeof(target_buf));

	/* Emit NODE_MAP line with pointer addresses */
	write_trace("NODE_MAP,%p,%p,%s,%d,%s\n",
				(void *)planstate->instrument,
				parent ? (void *)parent->instrument : NULL,
				node_type,
				depth,
				target);

	/* Recurse to children */
	emit_node_mapping(planstate->lefttree, planstate, depth + 1);
	emit_node_mapping(planstate->righttree, planstate, depth + 1);

	/* Handle special node types with additional children */
	switch (nodeTag(planstate))
	{
		case T_AppendState:
		{
			AppendState *as = (AppendState *) planstate;
			int i;
			for (i = 0; i < as->as_nplans; i++)
				emit_node_mapping(as->appendplans[i], planstate, depth + 1);
			break;
		}

		case T_MergeAppendState:
		{
			MergeAppendState *ms = (MergeAppendState *) planstate;
			int i;
			for (i = 0; i < ms->ms_nplans; i++)
				emit_node_mapping(ms->mergeplans[i], planstate, depth + 1);
			break;
		}

		case T_SubqueryScanState:
		{
			SubqueryScanState *ss = (SubqueryScanState *) planstate;
			emit_node_mapping(ss->subplan, planstate, depth + 1);
			break;
		}

		case T_BitmapAndState:
		{
			BitmapAndState *bas = (BitmapAndState *) planstate;
			int i;
			for (i = 0; i < bas->nplans; i++)
				emit_node_mapping(bas->bitmapplans[i], planstate, depth + 1);
			break;
		}

		case T_BitmapOrState:
		{
			BitmapOrState *bos = (BitmapOrState *) planstate;
			int i;
			for (i = 0; i < bos->nplans; i++)
				emit_node_mapping(bos->bitmapplans[i], planstate, depth + 1);
			break;
		}

		default:
			break;
	}
}

/* Global node ID counter for stats (reset per query, matches plan IDs) */
static int stat_node_id_counter = 0;

/*
 * Emit execution statistics after query completes
 */
static void
emit_exec_stats(PlanState *planstate, int parent_id, int depth)
{
	const char *node_type;
	char target_buf[NAMEDATALEN];
	const char *target;
	Instrumentation *instr;
	int my_id;

	/* Basic stats */
	double rows = 0;
	double nloops = 0;
	double nfiltered = 0;

	/* Timing */
	double time_ms = 0;
	double startup_ms = 0;

	/* Buffer stats */
	int64 blks_hit = 0;
	int64 blks_read = 0;
	int64 temp_read = 0;
	int64 temp_written = 0;

	/* WAL stats */
	int64 wal_records = 0;
	int64 wal_bytes = 0;

	if (planstate == NULL)
		return;

	my_id = ++stat_node_id_counter;
	node_type = get_planstate_node_name(nodeTag(planstate));
	target = get_scan_target(planstate, target_buf, sizeof(target_buf));
	instr = planstate->instrument;

	if (instr)
	{
		/* Finalize instrumentation */
		InstrEndLoop(instr);

		rows = instr->ntuples;
		nloops = instr->nloops;
		nfiltered = instr->nfiltered1 + instr->nfiltered2;

		time_ms = instr->total * 1000.0;
		startup_ms = instr->startup * 1000.0;

		blks_hit = instr->bufusage.shared_blks_hit;
		blks_read = instr->bufusage.shared_blks_read;
		temp_read = instr->bufusage.temp_blks_read;
		temp_written = instr->bufusage.temp_blks_written;

		wal_records = instr->walusage.wal_records;
		wal_bytes = instr->walusage.wal_bytes;
	}

	/* Emit STAT line */
	write_trace("STAT,%d,%d,%d,%s,%.0f,%.0f,%.0f,%.3f,%.3f,%ld,%ld,%ld,%ld,%ld,%ld,%s,%p\n",
				my_id,
				parent_id,
				depth,
				node_type,
				rows,
				nloops,
				nfiltered,
				time_ms,
				startup_ms,
				blks_hit,
				blks_read,
				temp_read,
				temp_written,
				wal_records,
				wal_bytes,
				target,
				(void *)instr);  /* Include instr pointer for correlation */

	emit_node_specific_info(planstate, my_id);

	/* Recurse */
	emit_exec_stats(planstate->lefttree, my_id, depth + 1);
	emit_exec_stats(planstate->righttree, my_id, depth + 1);

	switch (nodeTag(planstate))
	{
		case T_AppendState:
		{
			AppendState *as = (AppendState *) planstate;
			int i;
			for (i = 0; i < as->as_nplans; i++)
				emit_exec_stats(as->appendplans[i], my_id, depth + 1);
			break;
		}

		case T_MergeAppendState:
		{
			MergeAppendState *ms = (MergeAppendState *) planstate;
			int i;
			for (i = 0; i < ms->ms_nplans; i++)
				emit_exec_stats(ms->mergeplans[i], my_id, depth + 1);
			break;
		}

		case T_SubqueryScanState:
		{
			SubqueryScanState *ss = (SubqueryScanState *) planstate;
			emit_exec_stats(ss->subplan, my_id, depth + 1);
			break;
		}

		case T_BitmapAndState:
		{
			BitmapAndState *bas = (BitmapAndState *) planstate;
			int i;
			for (i = 0; i < bas->nplans; i++)
				emit_exec_stats(bas->bitmapplans[i], my_id, depth + 1);
			break;
		}

		case T_BitmapOrState:
		{
			BitmapOrState *bos = (BitmapOrState *) planstate;
			int i;
			for (i = 0; i < bos->nplans; i++)
				emit_exec_stats(bos->bitmapplans[i], my_id, depth + 1);
			break;
		}

		default:
			break;
	}
}

/*
 * Emit node-specific detailed information
 */
static void
emit_node_specific_info(PlanState *planstate, int node_id)
{
	if (planstate == NULL)
		return;

	switch (nodeTag(planstate))
	{
		case T_SortState:
		{
			SortState *sortstate = (SortState *) planstate;
			if (sortstate->sort_Done && sortstate->tuplesortstate)
			{
				TuplesortInstrumentation stats;
				const char *sort_method;
				const char *space_type;

				tuplesort_get_stats((Tuplesortstate *) sortstate->tuplesortstate, &stats);

				switch (stats.sortMethod)
				{
					case SORT_TYPE_TOP_N_HEAPSORT: sort_method = "top-N heapsort"; break;
					case SORT_TYPE_QUICKSORT:      sort_method = "quicksort"; break;
					case SORT_TYPE_EXTERNAL_SORT:  sort_method = "external sort"; break;
					case SORT_TYPE_EXTERNAL_MERGE: sort_method = "external merge"; break;
					default:                       sort_method = "unknown"; break;
				}

				switch (stats.spaceType)
				{
					case SORT_SPACE_TYPE_DISK:   space_type = "Disk"; break;
					case SORT_SPACE_TYPE_MEMORY: space_type = "Memory"; break;
					default:                     space_type = "unknown"; break;
				}

				write_trace("SORT,%d,%s,%s,%ld\n", node_id, sort_method, space_type, stats.spaceUsed);
			}
			break;
		}

		case T_HashState:
		{
			HashState *hashstate = (HashState *) planstate;
			HashJoinTable hashtable = hashstate->hashtable;
			if (hashtable)
			{
				write_trace("HASH,%d,%d,%d,%ld,%ld\n",
							node_id,
							hashtable->nbuckets,
							hashtable->nbatch,
							(long)(hashtable->spaceUsed / 1024),
							(long)(hashtable->spacePeak / 1024));
			}
			break;
		}

		case T_HashJoinState:
		{
			HashJoinState *hjstate = (HashJoinState *) planstate;
			HashJoinTable hashtable = hjstate->hj_HashTable;
			if (hashtable)
			{
				write_trace("HASHJOIN,%d,%d,%d,%ld,%ld\n",
							node_id,
							hashtable->nbuckets,
							hashtable->nbatch,
							(long)(hashtable->spaceUsed / 1024),
							(long)(hashtable->spacePeak / 1024));
			}
			break;
		}

		case T_IndexScanState:
		{
			IndexScanState *iss = (IndexScanState *) planstate;
			if (iss->ss.ss_currentRelation && iss->iss_RelationDesc)
			{
				write_trace("INDEX,%d,%s,%s\n",
							node_id,
							RelationGetRelationName(iss->iss_RelationDesc),
							RelationGetRelationName(iss->ss.ss_currentRelation));
			}
			break;
		}

		case T_IndexOnlyScanState:
		{
			IndexOnlyScanState *ioss = (IndexOnlyScanState *) planstate;
			if (ioss->ioss_RelationDesc && ioss->ss.ss_currentRelation)
			{
				write_trace("INDEXONLY,%d,%s,%s\n",
							node_id,
							RelationGetRelationName(ioss->ioss_RelationDesc),
							RelationGetRelationName(ioss->ss.ss_currentRelation));
			}
			break;
		}

		case T_BitmapIndexScanState:
		{
			BitmapIndexScanState *biss = (BitmapIndexScanState *) planstate;
			if (biss->biss_RelationDesc)
			{
				write_trace("BITMAPINDEX,%d,%s\n",
							node_id,
							RelationGetRelationName(biss->biss_RelationDesc));
			}
			break;
		}

		default:
			break;
	}
}

/*
 * Planner hook
 */
static PlannedStmt *
pg10046_planner(Query *parse, const char *query_string,
                int cursorOptions, ParamListInfo boundParams)
{
	PlannedStmt *result;
	int64 plan_start = 0;
	int64 plan_end = 0;

	if (pg10046_enabled)
		plan_start = get_trace_timestamp();

	if (prev_planner_hook)
		result = prev_planner_hook(parse, query_string, cursorOptions, boundParams);
	else
		result = standard_planner(parse, query_string, cursorOptions, boundParams);

	if (pg10046_enabled && result)
	{
		plan_end = get_trace_timestamp();

		open_trace_file();

		if (trace_state.active)
		{
			trace_state.query_id++;
			trace_state.plan_start_time = plan_start;
			trace_state.plan_end_time = plan_end;

			write_trace("QUERY_START,%ld,%lu,sql=%s\n",
						plan_start, trace_state.query_id,
						query_string ? query_string : "");

			emit_bind_variables(boundParams);
			trace_state.bound_params = boundParams;

			plan_node_id_counter = 0;
			write_trace("PLAN_START\n");
			emit_plan_tree(result->planTree, 0, 1, result);
			write_trace("PLAN_END\n");

			write_trace("PLAN_TIME,%ld\n", plan_end - plan_start);

			fsync(trace_state.trace_fd);
		}
	}

	return result;
}

/*
 * ExecutorStart hook
 */
static void
pg10046_ExecutorStart(QueryDesc *queryDesc, int eflags)
{
	if (pg10046_enabled)
	{
		if (queryDesc->instrument_options == 0)
			queryDesc->instrument_options = INSTRUMENT_ALL;
		else
			queryDesc->instrument_options |= INSTRUMENT_ALL;

		/* Reset wrapped nodes array for this query */
		reset_wrapped_nodes();
	}

	if (prev_ExecutorStart)
		prev_ExecutorStart(queryDesc, eflags);
	else
		standard_ExecutorStart(queryDesc, eflags);

	/*
	 * After standard_ExecutorStart, wrap all nodes to emit NODE_ENTER/NODE_EXIT.
	 * We store original ExecProcNode in our own array, NOT in ExecProcNodeReal.
	 */
	if (pg10046_enabled && queryDesc->planstate)
	{
		wrap_planstate_nodes(queryDesc->planstate);
	}
}

/*
 * ExecutorRun hook
 */
static void
pg10046_ExecutorRun(QueryDesc *queryDesc, ScanDirection direction,
                     uint64 count, bool execute_once)
{
	bool should_trace = pg10046_enabled && queryDesc->planstate;

	if (should_trace && trace_state.active)
	{
		trace_state.exec_start_time = get_trace_timestamp();
		trace_state.nesting_level++;
		trace_state.current_planstate = queryDesc->planstate;
		trace_state.call_stack_depth = 0;

		write_trace("EXEC_START,%ld,%lu\n",
					trace_state.exec_start_time,
					trace_state.query_id);

		emit_node_mapping(queryDesc->planstate, NULL, 1);

		/* Start periodic sampling */
		setup_sampling_timer();

		fsync(trace_state.trace_fd);
	}

	/* Call original executor */
	if (prev_ExecutorRun)
		prev_ExecutorRun(queryDesc, direction, count, execute_once);
	else
		standard_ExecutorRun(queryDesc, direction, count, execute_once);

	/* Process any final pending sample */
	if (should_trace && trace_state.active)
	{
		process_pending_sample();
	}
}

/*
 * Emit NODE_END for nodes that started but didn't finish naturally.
 * This handles early-stopped nodes (LIMIT, EXISTS, etc.)
 * Uses last_call_time for accurate timestamps.
 */
static void
emit_early_stop_node_ends(void)
{
	int i;

	for (i = 0; i < num_wrapped_nodes; i++)
	{
		WrappedNode *wn = &wrapped_nodes[i];

		if (wn->started && !wn->finished)
		{
			PlanState *node = wn->node;
			Instrumentation *instr = node ? node->instrument : NULL;
			const char *node_name = node ? get_planstate_node_name(nodeTag(node)) : "Unknown";
			char target_buf[NAMEDATALEN];
			const char *target = "";
			int64 elapsed;

			if (node)
				target = get_scan_target(node, target_buf, sizeof(target_buf));

			elapsed = wn->last_call_time - wn->start_time;

			wn->finished = true;

			if (instr)
			{
				write_trace("NODE_END,%ld,%p,%s,tuples=%.0f,blks_hit=%ld,blks_read=%ld,time_us=%ld,%s,reason=EARLY_STOP\n",
							wn->last_call_time, (void *)instr, node_name,
							instr->tuplecount,
							instr->bufusage.shared_blks_hit,
							instr->bufusage.shared_blks_read,
							elapsed,
							target);
			}
			else
			{
				write_trace("NODE_END,%ld,%p,%s,tuples=0,blks_hit=0,blks_read=0,time_us=%ld,%s,reason=EARLY_STOP\n",
							wn->last_call_time, (void *)instr, node_name,
							elapsed,
							target);
			}
		}
	}
}

/*
 * ExecutorEnd hook
 */
static void
pg10046_ExecutorEnd(QueryDesc *queryDesc)
{
	if (pg10046_enabled && trace_state.active && trace_state.nesting_level > 0)
	{
		int64 end_time = get_trace_timestamp();
		int64 elapsed = end_time - trace_state.exec_start_time;

		/* Stop sampling before collecting final stats */
		cancel_sampling_timer();

		/* Emit NODE_END for nodes stopped early by LIMIT, EXISTS, etc. */
		emit_early_stop_node_ends();

		stat_node_id_counter = 0;
		write_trace("STATS_START\n");
		emit_exec_stats(queryDesc->planstate, 0, 1);
		write_trace("STATS_END\n");

		write_trace("EXEC_END,%ld,%lu,ela=%ld\n",
					end_time,
					trace_state.query_id,
					elapsed);

		/* Stop eBPF tracing if active */
		if (trace_state.ebpf_active)
		{
			stop_ebpf_trace();
		}

		trace_state.nesting_level--;
		trace_state.current_planstate = NULL;
		trace_state.plan_start_time = 0;
		trace_state.plan_end_time = 0;
	}

	if (prev_ExecutorEnd)
		prev_ExecutorEnd(queryDesc);
	else
		standard_ExecutorEnd(queryDesc);
}
