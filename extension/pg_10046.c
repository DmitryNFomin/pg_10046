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

/* Background worker and shared memory */
#include "postmaster/bgworker.h"
#include "storage/ipc.h"
#include "storage/lwlock.h"
#include "storage/shmem.h"
#include "storage/spin.h"
#include "storage/pg_sema.h"
#include "storage/procsignal.h"
#include "storage/latch.h"

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
#include "utils/portal.h"  /* For Portal structure - late-attach support */
#include "tcop/pquery.h"   /* For ActivePortal global variable */

PG_MODULE_MAGIC;

void		_PG_init(void);
void		_PG_fini(void);

/* Forward declarations for eBPF daemon communication */
static void write_trace(const char *fmt, ...) pg_attribute_printf(1, 2);
static void start_ebpf_trace(void);
static void stop_ebpf_trace(void);

/* Forward declaration for late-attach (running query capture) */
static void capture_running_query(void);

/* Saved hook values */
static planner_hook_type prev_planner_hook = NULL;
static ExecutorStart_hook_type prev_ExecutorStart = NULL;
static ExecutorRun_hook_type prev_ExecutorRun = NULL;
static ExecutorEnd_hook_type prev_ExecutorEnd = NULL;

/* GUC variables */
static bool pg10046_enabled = false;
static bool pg10046_ebpf_enabled = false;  /* Also start eBPF IO tracing */
static bool pg10046_track_buffers = false; /* Track per-node buffer stats (EXPENSIVE - adds ~500% overhead!) */
static char *pg10046_trace_dir = NULL;
static char *pg10046_daemon_socket = NULL;  /* Default: /var/run/pg_10046.sock */
static int pg10046_sample_interval_ms = 10;  /* Sample every 10ms by default */
static int pg10046_progress_interval_tuples = 0;  /* Debug: emit PROGRESS every N tuples (0=disabled) */

/* Ring buffer GUC variables */
static int pg10046_ring_buffer_mb = 32;       /* Ring buffer size in MB (default 32MB) */
static int pg10046_flush_interval_ms = 1000;  /* Flush interval in ms (default 1 second) */

#define DEFAULT_DAEMON_SOCKET "/var/run/pg_10046.sock"
#define TRACE_SLOT_SIZE 512                   /* Size of each trace slot in bytes */
#define TRACE_SLOT_DATA_SIZE (TRACE_SLOT_SIZE - 16)  /* Data area per slot */
#define MAX_TRACED_BACKENDS 128               /* Max concurrent traced backends */

/*
 * Ring buffer slot for trace events.
 * Each slot is fixed-size to allow lock-free operations.
 */
typedef struct TraceSlot
{
	pg_atomic_uint32 state;      /* 0=free, 1=writing, 2=ready */
	uint32      pid;             /* Backend PID */
	uint16      len;             /* Data length */
	uint16      flags;           /* Reserved for future use */
	char        data[TRACE_SLOT_DATA_SIZE];  /* Trace event data */
} TraceSlot;

/* State values for TraceSlot.state */
#define SLOT_FREE    0
#define SLOT_WRITING 1
#define SLOT_READY   2

/*
 * Per-backend trace registration in shared memory.
 * Background worker uses this to know which files to write to.
 */
typedef struct TracedBackend
{
	pg_atomic_uint32 active;     /* 0=inactive, 1=active */
	uint32      pid;             /* Backend PID */
	char        trace_path[MAXPGPATH];  /* Output file path */
	char        trace_id[64];    /* Trace ID for correlation */
	char        trace_uuid[40];  /* UUID for correlation */
	uint64      start_time_ns;   /* Trace start time */
	pg_atomic_uint64 events_written;   /* Events written to file */
	pg_atomic_uint64 events_dropped;   /* Events dropped (buffer full) */
} TracedBackend;

/*
 * Cross-backend trace request structure.
 * Used when one session wants to enable tracing on another backend.
 */
typedef struct TraceRequest
{
	pg_atomic_uint32 requested;      /* 1 = trace requested, 0 = no request */
	pg_atomic_uint32 ebpf_active;    /* 1 = eBPF already started externally */
	int              requester_pid;  /* PID of requesting session (for logging) */
} TraceRequest;

/*
 * Shared memory control structure for the ring buffer.
 */
typedef struct RingBufferCtl
{
	/* Ring buffer pointers */
	pg_atomic_uint64 head;       /* Next slot to write (producers) */
	pg_atomic_uint64 tail;       /* Next slot to read (consumer) */
	uint64      num_slots;       /* Total number of slots */

	/* Statistics */
	pg_atomic_uint64 total_events;
	pg_atomic_uint64 dropped_events;

	/* Backend registration */
	TracedBackend backends[MAX_TRACED_BACKENDS];

	/* Worker state */
	pg_atomic_uint32 worker_running;
	Latch      *worker_latch;    /* For signaling the worker */

	/*
	 * Cross-backend trace requests.
	 * Indexed by backend ID (not PID). Use GetBackendIdFromPid() to find slot.
	 * When a session calls pg_10046.enable_trace(pid), it sets the flag here.
	 * Target backend checks this at query start and enables tracing.
	 */
	TraceRequest trace_requests[MAX_TRACED_BACKENDS];

	/* The actual ring buffer follows this structure in memory */
} RingBufferCtl;

/* Shared memory pointers */
static RingBufferCtl *ring_buffer_ctl = NULL;
static TraceSlot *ring_buffer_slots = NULL;

/* Saved hook for shared memory startup */
static shmem_startup_hook_type prev_shmem_startup_hook = NULL;

/* Background worker handle */
static BackgroundWorkerHandle *pg10046_worker_handle = NULL;

/* Function declarations for ring buffer operations */
static void pg10046_shmem_startup(void);
static Size pg10046_shmem_size(void);

/* Background worker entry point - must be non-static for dynamic lookup */
PGDLLEXPORT void pg10046_worker_main(Datum main_arg) pg_attribute_noreturn();

static bool ring_buffer_write(const char *data, int len);
static int  register_traced_backend(void);
static void unregister_traced_backend(int slot);

/* Per-backend slot for traced backend registration */
static int my_backend_slot = -1;

/* Maximum depth of node stack for tracking current execution */
#define MAX_NODE_STACK_DEPTH 64

/* Maximum number of nodes we can wrap */
#define MAX_WRAPPED_NODES 256

/* Per-backend state - defined early so ring buffer functions can use it */
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
	PlanState *call_stack[MAX_NODE_STACK_DEPTH];  /* Changed from Instrumentation* */

	/* For signal handler - pointer to current planstate root */
	PlanState  *current_planstate;

	/* eBPF tracing state */
	bool		ebpf_active;
	char		ebpf_trace_path[MAXPGPATH];

} TraceState;

static TraceState trace_state = {0};

/*
 * Calculate shared memory size for ring buffer.
 * Called during _PG_init to request shared memory.
 */
static Size
pg10046_shmem_size(void)
{
	Size		size;
	uint64		num_slots;

	/* Calculate number of slots that fit in configured MB */
	num_slots = ((uint64) pg10046_ring_buffer_mb * 1024 * 1024) / TRACE_SLOT_SIZE;

	/* Control structure */
	size = MAXALIGN(sizeof(RingBufferCtl));

	/* Ring buffer slots */
	size = add_size(size, mul_size(num_slots, sizeof(TraceSlot)));

	return size;
}

/*
 * Shared memory startup hook.
 * Initializes the ring buffer control structure and slots.
 */
static void
pg10046_shmem_startup(void)
{
	bool		found;
	Size		size;
	uint64		num_slots;
	int			i;

	/* Call previous hook if any */
	if (prev_shmem_startup_hook)
		prev_shmem_startup_hook();

	/* Create or attach to shared memory segment */
	LWLockAcquire(AddinShmemInitLock, LW_EXCLUSIVE);

	size = pg10046_shmem_size();
	ring_buffer_ctl = ShmemInitStruct("pg_10046 ring buffer",
									   size,
									   &found);

	if (!found)
	{
		/* First time - initialize the control structure */
		num_slots = ((uint64) pg10046_ring_buffer_mb * 1024 * 1024) / TRACE_SLOT_SIZE;

		/* Initialize control structure */
		pg_atomic_init_u64(&ring_buffer_ctl->head, 0);
		pg_atomic_init_u64(&ring_buffer_ctl->tail, 0);
		ring_buffer_ctl->num_slots = num_slots;
		pg_atomic_init_u64(&ring_buffer_ctl->total_events, 0);
		pg_atomic_init_u64(&ring_buffer_ctl->dropped_events, 0);
		pg_atomic_init_u32(&ring_buffer_ctl->worker_running, 0);
		ring_buffer_ctl->worker_latch = NULL;

		/* Initialize backend slots */
		for (i = 0; i < MAX_TRACED_BACKENDS; i++)
		{
			pg_atomic_init_u32(&ring_buffer_ctl->backends[i].active, 0);
			ring_buffer_ctl->backends[i].pid = 0;
			ring_buffer_ctl->backends[i].trace_path[0] = '\0';
			ring_buffer_ctl->backends[i].trace_id[0] = '\0';
			ring_buffer_ctl->backends[i].trace_uuid[0] = '\0';
			ring_buffer_ctl->backends[i].start_time_ns = 0;
			pg_atomic_init_u64(&ring_buffer_ctl->backends[i].events_written, 0);
			pg_atomic_init_u64(&ring_buffer_ctl->backends[i].events_dropped, 0);

			/* Initialize trace request slots */
			pg_atomic_init_u32(&ring_buffer_ctl->trace_requests[i].requested, 0);
			pg_atomic_init_u32(&ring_buffer_ctl->trace_requests[i].ebpf_active, 0);
			ring_buffer_ctl->trace_requests[i].requester_pid = 0;
		}

		/* Point to the ring buffer slots (after control structure) */
		ring_buffer_slots = (TraceSlot *) ((char *) ring_buffer_ctl +
										   MAXALIGN(sizeof(RingBufferCtl)));

		/* Initialize all slots as free */
		for (i = 0; i < (int) num_slots; i++)
		{
			pg_atomic_init_u32(&ring_buffer_slots[i].state, SLOT_FREE);
			ring_buffer_slots[i].pid = 0;
			ring_buffer_slots[i].len = 0;
			ring_buffer_slots[i].flags = 0;
		}

		elog(LOG, "pg_10046: initialized ring buffer with %lu slots (%d MB)",
			 num_slots, pg10046_ring_buffer_mb);
	}
	else
	{
		/* Attach to existing - just need to set up our local pointer */
		ring_buffer_slots = (TraceSlot *) ((char *) ring_buffer_ctl +
										   MAXALIGN(sizeof(RingBufferCtl)));
	}

	LWLockRelease(AddinShmemInitLock);
}

/*
 * Register current backend as traced.
 * Returns slot index, or -1 if no slots available.
 */
static int
register_traced_backend(void)
{
	int		i;

	if (ring_buffer_ctl == NULL)
		return -1;

	/* Find a free slot */
	for (i = 0; i < MAX_TRACED_BACKENDS; i++)
	{
		uint32 expected = 0;

		if (pg_atomic_compare_exchange_u32(&ring_buffer_ctl->backends[i].active,
										   &expected, 1))
		{
			/* Got the slot - fill in details */
			ring_buffer_ctl->backends[i].pid = MyProcPid;
			strlcpy(ring_buffer_ctl->backends[i].trace_path,
					trace_state.trace_path, MAXPGPATH);
			strlcpy(ring_buffer_ctl->backends[i].trace_id,
					trace_state.trace_id, sizeof(ring_buffer_ctl->backends[i].trace_id));
			strlcpy(ring_buffer_ctl->backends[i].trace_uuid,
					trace_state.trace_uuid, sizeof(ring_buffer_ctl->backends[i].trace_uuid));
			ring_buffer_ctl->backends[i].start_time_ns = trace_state.start_time_ns;
			pg_atomic_write_u64(&ring_buffer_ctl->backends[i].events_written, 0);
			pg_atomic_write_u64(&ring_buffer_ctl->backends[i].events_dropped, 0);

			/* Memory barrier to ensure all writes are visible */
			pg_memory_barrier();

			return i;
		}
	}

	elog(WARNING, "pg_10046: no available slots for traced backend (max %d)",
		 MAX_TRACED_BACKENDS);
	return -1;
}

/*
 * Unregister backend from traced list.
 */
static void
unregister_traced_backend(int slot)
{
	if (ring_buffer_ctl == NULL || slot < 0 || slot >= MAX_TRACED_BACKENDS)
		return;

	/* Clear the slot */
	ring_buffer_ctl->backends[slot].pid = 0;
	ring_buffer_ctl->backends[slot].trace_path[0] = '\0';

	/* Memory barrier before marking inactive */
	pg_memory_barrier();

	pg_atomic_write_u32(&ring_buffer_ctl->backends[slot].active, 0);
}

/*
 * Write trace event to ring buffer (lock-free).
 * Returns true on success, false if buffer full (event dropped).
 *
 * This is designed to be fast and non-blocking:
 * 1. Atomically claim a slot (increment head)
 * 2. Check if slot is within bounds (not overwriting unread data)
 * 3. Write data and mark slot as ready
 * 4. Signal background worker
 */
static bool
ring_buffer_write(const char *data, int len)
{
	uint64		head;
	uint64		tail;
	uint64		slot_idx;
	TraceSlot  *slot;
	uint32		expected;

	if (ring_buffer_ctl == NULL || ring_buffer_slots == NULL)
		return false;

	/* Truncate if too long */
	if (len > TRACE_SLOT_DATA_SIZE - 1)
		len = TRACE_SLOT_DATA_SIZE - 1;

	/*
	 * Atomically claim a slot by incrementing head.
	 * Use fetch_add which returns the old value.
	 */
	head = pg_atomic_fetch_add_u64(&ring_buffer_ctl->head, 1);
	slot_idx = head % ring_buffer_ctl->num_slots;

	/*
	 * Check if we're about to overwrite data that hasn't been read yet.
	 * If head - tail >= num_slots, the buffer is full.
	 */
	tail = pg_atomic_read_u64(&ring_buffer_ctl->tail);
	if (head - tail >= ring_buffer_ctl->num_slots)
	{
		/* Buffer full - drop event */
		pg_atomic_fetch_add_u64(&ring_buffer_ctl->dropped_events, 1);

		if (my_backend_slot >= 0)
			pg_atomic_fetch_add_u64(&ring_buffer_ctl->backends[my_backend_slot].events_dropped, 1);

		/* Log warning periodically (every 1000 drops) */
		{
			uint64 dropped = pg_atomic_read_u64(&ring_buffer_ctl->dropped_events);
			if (dropped % 1000 == 0)
			{
				elog(WARNING, "pg_10046: ring buffer full, %lu events dropped",
					 dropped);
			}
		}

		return false;
	}

	slot = &ring_buffer_slots[slot_idx];

	/*
	 * Wait for slot to be free (in case consumer hasn't processed it yet).
	 * This should be rare with a properly sized buffer.
	 */
	expected = SLOT_FREE;
	while (!pg_atomic_compare_exchange_u32(&slot->state, &expected, SLOT_WRITING))
	{
		expected = SLOT_FREE;
		pg_spin_delay();
	}

	/* Write data */
	slot->pid = MyProcPid;
	slot->len = len;
	slot->flags = 0;
	memcpy(slot->data, data, len);
	slot->data[len] = '\0';

	/* Mark slot as ready for consumer */
	pg_memory_barrier();
	pg_atomic_write_u32(&slot->state, SLOT_READY);

	/* Update statistics */
	pg_atomic_fetch_add_u64(&ring_buffer_ctl->total_events, 1);
	if (my_backend_slot >= 0)
		pg_atomic_fetch_add_u64(&ring_buffer_ctl->backends[my_backend_slot].events_written, 1);

	/* Signal worker that there's data to write */
	if (ring_buffer_ctl->worker_latch != NULL)
		SetLatch(ring_buffer_ctl->worker_latch);

	return true;
}

/* Signal handling for background worker */
static volatile sig_atomic_t pg10046_got_sigterm = false;
static volatile sig_atomic_t pg10046_got_sighup = false;

static void
pg10046_sigterm_handler(SIGNAL_ARGS)
{
	int save_errno = errno;
	pg10046_got_sigterm = true;
	SetLatch(MyLatch);
	errno = save_errno;
}

static void
pg10046_sighup_handler(SIGNAL_ARGS)
{
	int save_errno = errno;
	pg10046_got_sighup = true;
	SetLatch(MyLatch);
	errno = save_errno;
}

/*
 * Background worker main function.
 * Reads trace events from ring buffer and writes them to trace files.
 */
void
pg10046_worker_main(Datum main_arg)
{
	int			fd_cache[MAX_TRACED_BACKENDS];
	int			i;

	/* Initialize file descriptor cache */
	for (i = 0; i < MAX_TRACED_BACKENDS; i++)
		fd_cache[i] = -1;

	/* Establish signal handlers */
	pqsignal(SIGTERM, pg10046_sigterm_handler);
	pqsignal(SIGHUP, pg10046_sighup_handler);

	/* We're now ready to receive signals */
	BackgroundWorkerUnblockSignals();

	/* Register our latch with the ring buffer */
	if (ring_buffer_ctl != NULL)
	{
		ring_buffer_ctl->worker_latch = MyLatch;
		pg_atomic_write_u32(&ring_buffer_ctl->worker_running, 1);
	}

	elog(LOG, "pg_10046: trace writer background worker started");

	/* Main loop */
	while (!pg10046_got_sigterm)
	{
		uint64		tail;
		uint64		head;
		bool		did_work = false;
		int			rc;

		/* Check for config reload */
		if (pg10046_got_sighup)
		{
			pg10046_got_sighup = false;
			ProcessConfigFile(PGC_SIGHUP);
		}

		/* Process pending trace events */
		if (ring_buffer_ctl != NULL && ring_buffer_slots != NULL)
		{
			tail = pg_atomic_read_u64(&ring_buffer_ctl->tail);
			head = pg_atomic_read_u64(&ring_buffer_ctl->head);

			while (tail < head)
			{
				uint64		slot_idx = tail % ring_buffer_ctl->num_slots;
				TraceSlot  *slot = &ring_buffer_slots[slot_idx];
				uint32		state;

				/* Check if slot is ready */
				state = pg_atomic_read_u32(&slot->state);
				if (state != SLOT_READY)
				{
					/* Slot not ready yet, try later */
					break;
				}

				/* Find the trace file for this backend */
				{
					int		backend_slot = -1;
					uint32	pid = slot->pid;

					/* Look up backend by PID */
					for (i = 0; i < MAX_TRACED_BACKENDS; i++)
					{
						if (pg_atomic_read_u32(&ring_buffer_ctl->backends[i].active) &&
							ring_buffer_ctl->backends[i].pid == pid)
						{
							backend_slot = i;
							break;
						}
					}

					if (backend_slot >= 0)
					{
						/* Open file if not cached */
						if (fd_cache[backend_slot] < 0)
						{
							fd_cache[backend_slot] = open(
								ring_buffer_ctl->backends[backend_slot].trace_path,
								O_WRONLY | O_CREAT | O_APPEND,
								S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

							if (fd_cache[backend_slot] < 0)
							{
								elog(WARNING, "pg_10046: could not open trace file %s: %m",
									 ring_buffer_ctl->backends[backend_slot].trace_path);
							}
						}

						/* Write to file */
						if (fd_cache[backend_slot] >= 0)
						{
							ssize_t ret pg_attribute_unused();
							ret = write(fd_cache[backend_slot], slot->data, slot->len);
						}
					}
				}

				/* Mark slot as free */
				pg_atomic_write_u32(&slot->state, SLOT_FREE);

				/* Advance tail */
				pg_atomic_fetch_add_u64(&ring_buffer_ctl->tail, 1);
				tail++;
				did_work = true;
			}

			/* Close files for inactive backends */
			for (i = 0; i < MAX_TRACED_BACKENDS; i++)
			{
				if (fd_cache[i] >= 0 &&
					!pg_atomic_read_u32(&ring_buffer_ctl->backends[i].active))
				{
					/* Backend is done - sync and close file */
					fsync(fd_cache[i]);
					close(fd_cache[i]);
					fd_cache[i] = -1;
				}
			}
		}

		/* Wait for work or timeout */
		rc = WaitLatch(MyLatch,
					   WL_LATCH_SET | WL_TIMEOUT | WL_EXIT_ON_PM_DEATH,
					   did_work ? 0 : pg10046_flush_interval_ms,
					   PG_WAIT_EXTENSION);

		if (rc & WL_LATCH_SET)
			ResetLatch(MyLatch);
	}

	/* Cleanup */
	if (ring_buffer_ctl != NULL)
	{
		pg_atomic_write_u32(&ring_buffer_ctl->worker_running, 0);
		ring_buffer_ctl->worker_latch = NULL;
	}

	/* Close all cached file descriptors */
	for (i = 0; i < MAX_TRACED_BACKENDS; i++)
	{
		if (fd_cache[i] >= 0)
		{
			fsync(fd_cache[i]);
			close(fd_cache[i]);
		}
	}

	elog(LOG, "pg_10046: trace writer background worker stopped");
	proc_exit(0);
}

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

	/* Self-tracked stats (avoid PostgreSQL's expensive Instrumentation) */
	int64       tuples_returned;    /* Count of non-NULL tuples returned */
} WrappedNode;

static WrappedNode wrapped_nodes[MAX_WRAPPED_NODES];
static int num_wrapped_nodes = 0;

/* Inline cache for find_wrapped_node - huge win since same node is looked up repeatedly */
static PlanState *wn_cache_node = NULL;
static WrappedNode *wn_cache_result = NULL;

/*
 * Local trace buffer for batching writes.
 * Instead of writing each event to ring buffer separately (expensive atomic ops),
 * we accumulate all events in a local buffer and flush once at query end.
 * This dramatically reduces overhead for small queries.
 */
#define LOCAL_TRACE_BUF_SIZE (128 * 1024)  /* 128KB - enough for most queries */
static char *local_trace_buf = NULL;
static int local_trace_buf_pos = 0;
static bool local_trace_buf_active = false;

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
static void write_trace_direct(const char *fmt, ...) pg_attribute_printf(1, 2);
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
	PlanState *current_node = NULL;

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

	trace_state.sample_count++;

	/* Format and write - snprintf and write are signal-safe.
	 * Note: we no longer have tuple/buffer stats in signal context since
	 * we disabled PostgreSQL's expensive instrumentation.
	 */
	len = snprintf(buf, sizeof(buf), "SAMPLE,%ld,%p,0x%08X,%d,0,0,0\n",
				   now, (void *)current_node, wait_event, trace_state.sample_count);

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
	PlanState *current_node = NULL;
	const char *wait_class;

	if (!sample_pending || !trace_state.sampling_active)
		return;

	sample_pending = 0;

	now = get_trace_timestamp();
	wait_event = get_current_wait_event();
	wait_class = get_wait_event_class_name(wait_event);

	/* Get current node from call stack */
	{
		int depth = trace_state.call_stack_depth;
		if (depth > 0 && depth <= MAX_NODE_STACK_DEPTH)
			current_node = trace_state.call_stack[depth - 1];
	}

	/* Only emit sample if we have a wait event or are in a node */
	if (wait_event != 0 || current_node != NULL)
	{
		trace_state.sample_count++;

		/*
		 * SAMPLE format (simplified - no per-tuple stats without instrumentation):
		 * SAMPLE,timestamp,node_ptr,wait_event_info,wait_class,sample_num,0,0,0
		 */
		write_trace_nonblock("SAMPLE,%ld,%p,0x%08X,%s,%d,0,0,0\n",
							 now,
							 (void *)current_node,
							 wait_event,
							 wait_class,
							 trace_state.sample_count);
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
 * Using pg_write_barrier() (lighter than pg_memory_barrier()) since
 * we only need write ordering - signal handler does reads.
 */
static inline void
push_call_stack(PlanState *node)
{
	int depth = trace_state.call_stack_depth;
	if (depth < MAX_NODE_STACK_DEPTH)
	{
		trace_state.call_stack[depth] = node;
		/* Write barrier to ensure array write is visible before depth update */
		pg_write_barrier();
		trace_state.call_stack_depth = depth + 1;
	}
}

/*
 * Pop node from call stack (called on EVERY ExecProcNode exit)
 *
 * Signal safety: Just decrement depth. The old array entry doesn't matter
 * because signal handler checks depth first.
 */
static inline void
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
	/* Invalidate inline cache */
	wn_cache_node = NULL;
	wn_cache_result = NULL;
}

/*
 * Start buffering trace output.
 * All subsequent write_trace calls will append to local buffer
 * instead of immediately writing to ring buffer.
 */
static void
start_trace_buffering(void)
{
	if (local_trace_buf == NULL)
	{
		/* Allocate in TopMemoryContext so it persists across queries */
		MemoryContext oldctx = MemoryContextSwitchTo(TopMemoryContext);
		local_trace_buf = palloc(LOCAL_TRACE_BUF_SIZE);
		MemoryContextSwitchTo(oldctx);
	}
	local_trace_buf_pos = 0;
	local_trace_buf_active = true;
}

/*
 * Flush buffered trace output directly to file.
 * Called at query end to write all accumulated events in one shot.
 *
 * IMPORTANT: We always use direct write() here, bypassing ring buffer.
 * The ring buffer's per-event atomic operations are the main source of
 * overhead - by buffering locally and writing once, we eliminate that.
 */
static void
flush_trace_buffer(void)
{
	ssize_t ret pg_attribute_unused();

	if (!local_trace_buf_active || local_trace_buf == NULL || local_trace_buf_pos == 0)
		return;

	local_trace_buf_active = false;  /* Prevent recursion */

	/* Single direct write - bypasses expensive ring buffer operations */
	if (trace_state.trace_fd > 0)
		ret = write(trace_state.trace_fd, local_trace_buf, local_trace_buf_pos);

	local_trace_buf_pos = 0;
}

/*
 * Find wrapped node entry for a given PlanState
 * Returns pointer to WrappedNode or NULL if not found
 *
 * Uses inline cache for fast repeated lookups (common case: same node
 * called thousands of times for scan operations)
 */
static inline WrappedNode *
find_wrapped_node(PlanState *node)
{
	int i;

	/* Fast path: cache hit (same node as last lookup) */
	if (node == wn_cache_node)
		return wn_cache_result;

	/* Slow path: linear search */
	for (i = 0; i < num_wrapped_nodes; i++)
	{
		if (wrapped_nodes[i].node == node)
		{
			/* Update cache */
			wn_cache_node = node;
			wn_cache_result = &wrapped_nodes[i];
			return wn_cache_result;
		}
	}

	/* Not found - cache the miss too to avoid repeated searches */
	wn_cache_node = node;
	wn_cache_result = NULL;
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
	int64 now;

	/* Find our wrapped node entry */
	wn = find_wrapped_node(node);
	if (wn == NULL)
	{
		elog(ERROR, "pg_10046: could not find wrapped node for %p", node);
		return NULL;
	}

	/*
	 * NODE_START: Emit on first call to this node (lifecycle event)
	 * Only compute expensive things (timestamp, node_name, target) on first call.
	 */
	if (!wn->started)
	{
		const char *node_name = get_planstate_node_name(nodeTag(node));
		char target_buf[NAMEDATALEN];
		const char *target = get_scan_target(node, target_buf, sizeof(target_buf));

		now = get_trace_timestamp();
		wn->started = true;
		wn->start_time = now;
		wn->last_call_time = now;
		wn->last_progress_tuples = 0;

		write_trace("NODE_START,%ld,%p,%s,%s\n",
					now, (void *)node, node_name, target);
	}

	/*
	 * PUSH onto call stack (only if sampling is enabled)
	 * This is the key to Alternative 3 - stack mirrors C call stack
	 */
	if (pg10046_sample_interval_ms > 0)
		push_call_stack(node);

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
	 * POP from call stack (only if sampling is enabled)
	 */
	if (pg10046_sample_interval_ms > 0)
		pop_call_stack();

	/*
	 * Count tuples ourselves (avoids expensive PostgreSQL Instrumentation)
	 */
	if (!TupIsNull(result))
		wn->tuples_returned++;

	/*
	 * PROGRESS: Emit every Y tuples (debug mode)
	 * Uses our self-tracked tuple count.
	 */
	if (pg10046_progress_interval_tuples > 0 && !TupIsNull(result))
	{
		int64 tuples_since_last = wn->tuples_returned - (int64)wn->last_progress_tuples;

		if (tuples_since_last >= pg10046_progress_interval_tuples)
		{
			const char *node_name = get_planstate_node_name(nodeTag(node));
			now = get_trace_timestamp();
			write_trace("PROGRESS,%ld,%p,%s,%ld,0,0\n",
						now, (void *)node, node_name,
						wn->tuples_returned);

			wn->last_progress_tuples = (double)wn->tuples_returned;
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
		const char *node_name = get_planstate_node_name(nodeTag(node));
		char target_buf[NAMEDATALEN];
		const char *target = get_scan_target(node, target_buf, sizeof(target_buf));
		Instrumentation *instr = node->instrument;
		int64 elapsed;
		int64 blks_hit = 0;
		int64 blks_read = 0;

		wn->finished = true;
		now = get_trace_timestamp();
		wn->last_call_time = now;  /* Update for accurate timing */
		elapsed = now - wn->start_time;

		/* Get buffer stats from instrumentation if available (track_buffers=on) */
		if (instr)
		{
			blks_hit = instr->bufusage.shared_blks_hit;
			blks_read = instr->bufusage.shared_blks_read;
		}

		/*
		 * First, cascade NODE_END to any unfinished children.
		 * This ensures children appear before parent in trace (correct order).
		 */
		cascade_node_end_to_children(node, now);

		/* Emit NODE_END with stats */
		write_trace("NODE_END,%ld,%p,%s,tuples=%ld,blks_hit=%ld,blks_read=%ld,time_us=%ld,%s\n",
					now, (void *)node, node_name,
					wn->tuples_returned,
					blks_hit,
					blks_read,
					elapsed,
					target);
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
		wrapped_nodes[num_wrapped_nodes].tuples_returned = 0;

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

/* ============================================================================
 * SQL Functions for cross-backend trace control
 * ============================================================================
 */

/*
 * Find backend slot index by PID.
 * Returns -1 if not found.
 */
static int
find_backend_slot_by_pid(int target_pid)
{
	int i;

	if (ring_buffer_ctl == NULL)
		return -1;

	/*
	 * Look through registered backends first - but we also need to handle
	 * backends that haven't started tracing yet. Use a simple linear search
	 * through all possible slots.
	 */
	for (i = 0; i < MAX_TRACED_BACKENDS; i++)
	{
		if (ring_buffer_ctl->backends[i].pid == (uint32) target_pid)
			return i;
	}

	/*
	 * Backend not found in registered list - return an available slot
	 * based on PID modulo. This ensures consistent slot for a given PID.
	 */
	return target_pid % MAX_TRACED_BACKENDS;
}

/*
 * pg_10046_enable_trace(target_pid int) - Enable tracing on another backend.
 *
 * Sets a flag in shared memory that the target backend will check at the
 * start of its next query. The target will then enable tracing.
 *
 * Returns true if the request was registered, false on error.
 */
PG_FUNCTION_INFO_V1(pg_10046_enable_trace);
Datum
pg_10046_enable_trace(PG_FUNCTION_ARGS)
{
	int			target_pid = PG_GETARG_INT32(0);
	int			slot;

	if (ring_buffer_ctl == NULL)
	{
		ereport(WARNING,
				(errmsg("pg_10046: shared memory not initialized")));
		PG_RETURN_BOOL(false);
	}

	/* Validate target PID exists (basic check) */
	if (target_pid <= 0)
	{
		ereport(WARNING,
				(errmsg("pg_10046: invalid target PID %d", target_pid)));
		PG_RETURN_BOOL(false);
	}

	/* Find slot for this backend */
	slot = find_backend_slot_by_pid(target_pid);
	if (slot < 0)
	{
		ereport(WARNING,
				(errmsg("pg_10046: could not find slot for PID %d", target_pid)));
		PG_RETURN_BOOL(false);
	}

	/* Set the trace request flag */
	ring_buffer_ctl->trace_requests[slot].requester_pid = MyProcPid;
	pg_atomic_write_u32(&ring_buffer_ctl->trace_requests[slot].requested, 1);

	elog(LOG, "pg_10046: trace requested for PID %d by PID %d (slot %d)",
		 target_pid, MyProcPid, slot);

	PG_RETURN_BOOL(true);
}

/*
 * pg_10046_enable_trace_ebpf(target_pid int) - Enable tracing with eBPF flag.
 *
 * Same as pg_10046_enable_trace but also sets ebpf_active flag to indicate
 * that eBPF tracing was already started externally (e.g., by CLI tool).
 * This prevents the extension from trying to start eBPF again.
 */
PG_FUNCTION_INFO_V1(pg_10046_enable_trace_ebpf);
Datum
pg_10046_enable_trace_ebpf(PG_FUNCTION_ARGS)
{
	int			target_pid = PG_GETARG_INT32(0);
	int			slot;

	if (ring_buffer_ctl == NULL)
	{
		ereport(WARNING,
				(errmsg("pg_10046: shared memory not initialized")));
		PG_RETURN_BOOL(false);
	}

	if (target_pid <= 0)
	{
		ereport(WARNING,
				(errmsg("pg_10046: invalid target PID %d", target_pid)));
		PG_RETURN_BOOL(false);
	}

	slot = find_backend_slot_by_pid(target_pid);
	if (slot < 0)
	{
		ereport(WARNING,
				(errmsg("pg_10046: could not find slot for PID %d", target_pid)));
		PG_RETURN_BOOL(false);
	}

	/* Set both flags - trace requested AND eBPF already active */
	ring_buffer_ctl->trace_requests[slot].requester_pid = MyProcPid;
	pg_atomic_write_u32(&ring_buffer_ctl->trace_requests[slot].ebpf_active, 1);
	pg_atomic_write_u32(&ring_buffer_ctl->trace_requests[slot].requested, 1);

	elog(LOG, "pg_10046: trace+eBPF requested for PID %d by PID %d (slot %d)",
		 target_pid, MyProcPid, slot);

	PG_RETURN_BOOL(true);
}

/*
 * pg_10046_disable_trace(target_pid int) - Disable tracing on another backend.
 *
 * Note: This only clears the request flag. If tracing is already active,
 * it will continue until the session disables it or ends.
 */
PG_FUNCTION_INFO_V1(pg_10046_disable_trace);
Datum
pg_10046_disable_trace(PG_FUNCTION_ARGS)
{
	int			target_pid = PG_GETARG_INT32(0);
	int			slot;

	if (ring_buffer_ctl == NULL)
		PG_RETURN_BOOL(false);

	slot = find_backend_slot_by_pid(target_pid);
	if (slot < 0)
		PG_RETURN_BOOL(false);

	/* Clear the trace request flags */
	pg_atomic_write_u32(&ring_buffer_ctl->trace_requests[slot].requested, 0);
	pg_atomic_write_u32(&ring_buffer_ctl->trace_requests[slot].ebpf_active, 0);
	ring_buffer_ctl->trace_requests[slot].requester_pid = 0;

	elog(LOG, "pg_10046: trace request cleared for PID %d", target_pid);

	PG_RETURN_BOOL(true);
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

	DefineCustomBoolVariable("pg_10046.track_buffers",
							 "Track per-node buffer statistics (WARNING: ~500% overhead!)",
							 "When enabled, tracks shared_blks_hit/read per node using "
							 "PostgreSQL's native instrumentation. This is EXPENSIVE and "
							 "adds approximately 500% overhead. Only enable when you need "
							 "detailed per-node buffer attribution.",
							 &pg10046_track_buffers,
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

	DefineCustomIntVariable("pg_10046.ring_buffer_mb",
							"Size of ring buffer for trace events in MB",
							"Trace events are buffered in shared memory and written "
							"to disk by a background worker. Default is 32MB.",
							&pg10046_ring_buffer_mb,
							32,     /* default 32MB */
							1,      /* min 1MB */
							1024,   /* max 1GB */
							PGC_POSTMASTER,
							GUC_UNIT_MB,
							NULL, NULL, NULL);

	DefineCustomIntVariable("pg_10046.flush_interval_ms",
							"Interval for flushing trace buffer to disk in ms",
							"Background worker flushes accumulated trace events "
							"to disk at this interval. Default is 1000ms.",
							&pg10046_flush_interval_ms,
							1000,   /* default 1 second */
							100,    /* min 100ms */
							60000,  /* max 60 seconds */
							PGC_SIGHUP,
							GUC_UNIT_MS,
							NULL, NULL, NULL);

	/*
	 * Request shared memory for ring buffer.
	 * This must be done in _PG_init before shared memory is allocated.
	 */
	RequestAddinShmemSpace(pg10046_shmem_size());
	RequestNamedLWLockTranche("pg_10046", 1);

	/*
	 * Register background worker.
	 * The worker will be started when PostgreSQL starts.
	 */
	{
		BackgroundWorker worker;

		memset(&worker, 0, sizeof(worker));
		worker.bgw_flags = BGWORKER_SHMEM_ACCESS;
		worker.bgw_start_time = BgWorkerStart_PostmasterStart;
		worker.bgw_restart_time = BGW_NEVER_RESTART;
		snprintf(worker.bgw_library_name, BGW_MAXLEN, "pg_10046");
		snprintf(worker.bgw_function_name, BGW_MAXLEN, "pg10046_worker_main");
		snprintf(worker.bgw_name, BGW_MAXLEN, "pg_10046 trace writer");
		snprintf(worker.bgw_type, BGW_MAXLEN, "pg_10046 trace writer");
		worker.bgw_main_arg = (Datum) 0;
		worker.bgw_notify_pid = 0;

		RegisterBackgroundWorker(&worker);
	}

	/*
	 * Install shared memory startup hook.
	 * This will initialize the ring buffer when shared memory is ready.
	 */
	prev_shmem_startup_hook = shmem_startup_hook;
	shmem_startup_hook = pg10046_shmem_startup;

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

	/* Unregister from ring buffer before closing trace file */
	if (my_backend_slot >= 0)
	{
		unregister_traced_backend(my_backend_slot);
		my_backend_slot = -1;
	}

	/* Close trace file */
	if (trace_state.trace_fd > 0)
	{
		close(trace_state.trace_fd);
		trace_state.trace_fd = 0;
	}

	/* Restore shmem startup hook */
	shmem_startup_hook = prev_shmem_startup_hook;

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

	/*
	 * Write trace header DIRECTLY (not through ring buffer).
	 * This prevents race conditions where SAMPLE events from the timeout
	 * handler (which also writes directly) could appear before the header.
	 */
	write_trace_direct("# PG_10046 TRACE\n");
	write_trace_direct("# TRACE_ID: %s\n", trace_state.trace_id);
	write_trace_direct("# TRACE_UUID: %s\n", trace_state.trace_uuid);
	write_trace_direct("# PID: %d\n", MyProcPid);
	write_trace_direct("# START_TIME: %lu\n", (unsigned long) trace_state.start_time_ns);
	write_trace_direct("# SAMPLE_INTERVAL_MS: %d\n", pg10046_sample_interval_ms);
	write_trace_direct("# EBPF_ENABLED: %s\n", pg10046_ebpf_enabled ? "true" : "false");
	write_trace_direct("# RING_BUFFER_MB: %d\n", pg10046_ring_buffer_mb);
	write_trace_direct("# RING_BUFFER_ACTIVE: %s\n",
				(ring_buffer_ctl && pg_atomic_read_u32(&ring_buffer_ctl->worker_running)) ?
				"true" : "false");
	write_trace_direct("#\n");

	/* Start eBPF tracing if enabled (and not already started externally) */
	if (trace_state.ebpf_active)
	{
		/* eBPF was already started externally (e.g., by pg_10046_attach CLI) */
		write_trace_direct("# eBPF tracing: EXTERNAL (started by CLI tool)\n");
		write_trace_direct("#\n");
	}
	else if (pg10046_ebpf_enabled)
	{
		start_ebpf_trace();
	}
	else
	{
		write_trace_direct("# To collect IO events manually, start eBPF tracer:\n");
		write_trace_direct("#   pg_10046_ebpf.sh start %d %s\n", MyProcPid, trace_state.trace_uuid);
		write_trace_direct("# eBPF trace file: pg_10046_io_%s.trc\n", trace_state.trace_id);
		write_trace_direct("#\n");
	}

	/* Now register this backend for ring buffer writes */
	my_backend_slot = register_traced_backend();

	/*
	 * LATE-ATTACH: Check if there's an already-running query.
	 * If so, capture its SQL, binds, plan, and NODE_MAP.
	 * This enables tracing to be enabled mid-query and still get
	 * full visibility into the running execution.
	 */
	capture_running_query();
}

/*
 * Write formatted line to trace file - DIRECT write (bypasses ring buffer).
 * Used for header writes that must appear before any ring buffer events.
 */
static void
write_trace_direct(const char *fmt, ...)
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
		len = Min(len, (int)sizeof(buf) - 1);
		ret = write(trace_state.trace_fd, buf, len);
	}
}

/*
 * Write formatted line to trace file.
 *
 * If local buffering is active, appends to local buffer (flushed at query end).
 * Otherwise, if ring buffer is available, writes through ring buffer.
 * Falls back to direct write as last resort.
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
		len = Min(len, (int)sizeof(buf) - 1);

		/*
		 * Fast path: if local buffering is active, append to local buffer.
		 * This eliminates per-event ring buffer overhead.
		 */
		if (local_trace_buf_active && local_trace_buf != NULL)
		{
			int remaining = LOCAL_TRACE_BUF_SIZE - local_trace_buf_pos;
			if (len < remaining)
			{
				memcpy(local_trace_buf + local_trace_buf_pos, buf, len);
				local_trace_buf_pos += len;
				return;
			}
			/* Buffer full - flush and retry */
			flush_trace_buffer();
			start_trace_buffering();
			if (len < LOCAL_TRACE_BUF_SIZE)
			{
				memcpy(local_trace_buf + local_trace_buf_pos, buf, len);
				local_trace_buf_pos += len;
				return;
			}
			/* Event too large for buffer, fall through to direct write */
		}

		/*
		 * Try ring buffer if available and worker is running.
		 */
		if (ring_buffer_ctl != NULL &&
			pg_atomic_read_u32(&ring_buffer_ctl->worker_running) &&
			my_backend_slot >= 0)
		{
			if (ring_buffer_write(buf, len))
				return;  /* Success - event written to ring buffer */
			/* Fall through to direct write on failure */
		}

		/* Direct write (fallback) */
		{
			ssize_t ret pg_attribute_unused();
			ret = write(trace_state.trace_fd, buf, len);
		}
	}
}

/*
 * Write trace without blocking (for use in/near signal context)
 * Uses smaller buffer and non-blocking semantics.
 * Ring buffer is safe to use here since it's lock-free.
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
		len = Min(len, (int)sizeof(buf) - 1);

		/*
		 * Try ring buffer first - it's lock-free and safe for signal context.
		 */
		if (ring_buffer_ctl != NULL &&
			pg_atomic_read_u32(&ring_buffer_ctl->worker_running) &&
			my_backend_slot >= 0)
		{
			if (ring_buffer_write(buf, len))
				return;
			/* Fall through to direct write on failure */
		}

		/* Non-blocking write - ignore errors */
		{
			ssize_t ret pg_attribute_unused();
			ret = write(trace_state.trace_fd, buf, len);
		}
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
 * Format: NODE_MAP,node_ptr,parent_node_ptr,node_type,depth,target
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

	/* Emit NODE_MAP line with PlanState pointer addresses */
	write_trace("NODE_MAP,%p,%p,%s,%d,%s\n",
				(void *)planstate,
				(void *)parent,
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

/*
 * LATE-ATTACH: Capture SQL, binds, plan, and NODE_MAP from an already-running query.
 *
 * This is called when tracing is enabled (e.g., SET pg_10046.enabled = true)
 * and there's already a query executing in this backend. ActivePortal points
 * to the currently executing portal, which contains all the query information.
 *
 * This allows "attaching" to a running query mid-execution, similar to how
 * Oracle's 10046 trace can be enabled at any time.
 */
static void
capture_running_query(void)
{
	Portal		portal;
	QueryDesc  *queryDesc;
	const char *sql;
	int64		now;

	/*
	 * Check if there's an active portal with a running query.
	 * ActivePortal is a global variable pointing to the currently executing portal.
	 */
	portal = ActivePortal;
	if (portal == NULL)
		return;

	/* Check if the portal has a queryDesc (i.e., query is actually running) */
	queryDesc = portal->queryDesc;
	if (queryDesc == NULL)
		return;

	/* Check if we have a planstate (execution has started) */
	if (queryDesc->planstate == NULL)
		return;

	/*
	 * We found a running query! Emit its information.
	 * Note: This query was already being executed before tracing was enabled,
	 * so we mark it specially in the trace output.
	 */
	write_trace("# LATE-ATTACH: Captured already-running query\n");

	now = get_trace_timestamp();
	trace_state.query_id++;

	/* Get SQL text - prefer portal's sourceText, fall back to queryDesc */
	sql = portal->sourceText;
	if (sql == NULL || sql[0] == '\0')
		sql = queryDesc->sourceText;
	if (sql == NULL)
		sql = "(unknown)";

	write_trace("QUERY_START,%ld,%lu,sql=%s\n",
				now, trace_state.query_id, sql);

	/* Emit bind variables from portal params */
	if (portal->portalParams)
	{
		emit_bind_variables(portal->portalParams);
		trace_state.bound_params = portal->portalParams;
	}

	/* Emit plan tree if we have access to it */
	if (queryDesc->plannedstmt && queryDesc->plannedstmt->planTree)
	{
		plan_node_id_counter = 0;
		write_trace("PLAN_START\n");
		emit_plan_tree(queryDesc->plannedstmt->planTree, 0, 1, queryDesc->plannedstmt);
		write_trace("PLAN_END\n");
	}

	/* Record execution start (approximation - actual start was earlier) */
	trace_state.exec_start_time = now;
	trace_state.nesting_level++;
	trace_state.current_planstate = queryDesc->planstate;
	trace_state.call_stack_depth = 0;

	write_trace("EXEC_START,%ld,%lu\n", now, trace_state.query_id);

	/* Emit NODE_MAP for eBPF attribution */
	emit_node_mapping(queryDesc->planstate, NULL, 1);

	/* Wrap nodes to track execution (if not already wrapped) */
	wrap_planstate_nodes(queryDesc->planstate);

	/* Start sampling timer for wait event capture */
	setup_sampling_timer();

	/* Only fsync if NOT using ring buffer (ring buffer worker handles flushing) */
	if (!(ring_buffer_ctl != NULL &&
		  pg_atomic_read_u32(&ring_buffer_ctl->worker_running) &&
		  my_backend_slot >= 0))
		fsync(trace_state.trace_fd);

	elog(LOG, "pg_10046: late-attach captured running query (pid=%d, query_id=%lu)",
		 MyProcPid, trace_state.query_id);
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
	WrappedNode *wn;
	int my_id;

	/* Basic stats - from our self-tracked data */
	int64 rows = 0;
	double time_ms = 0;

	/* Buffer stats from instrumentation (only when track_buffers=on) */
	int64 blks_hit = 0, blks_read = 0;
	int64 local_blks_hit = 0, local_blks_read = 0;
	int64 temp_blks_read = 0, temp_blks_written = 0;

	if (planstate == NULL)
		return;

	my_id = ++stat_node_id_counter;
	node_type = get_planstate_node_name(nodeTag(planstate));
	target = get_scan_target(planstate, target_buf, sizeof(target_buf));

	/* Get stats from our wrapped node tracking */
	wn = find_wrapped_node(planstate);
	if (wn)
	{
		rows = wn->tuples_returned;
		if (wn->start_time > 0 && wn->last_call_time > 0)
			time_ms = (wn->last_call_time - wn->start_time) / 1000.0;
	}

	if (pg10046_track_buffers && planstate->instrument)
	{
		Instrumentation *instr = planstate->instrument;
		blks_hit = instr->bufusage.shared_blks_hit;
		blks_read = instr->bufusage.shared_blks_read;
		local_blks_hit = instr->bufusage.local_blks_hit;
		local_blks_read = instr->bufusage.local_blks_read;
		temp_blks_read = instr->bufusage.temp_blks_read;
		temp_blks_written = instr->bufusage.temp_blks_written;
	}

	/* Emit STAT line */
	write_trace("STAT,%d,%d,%d,%s,%ld,1,0,%.3f,0.000,%ld,%ld,%ld,%ld,%ld,%ld,%s,%p\n",
				my_id,
				parent_id,
				depth,
				node_type,
				rows,
				time_ms,
				blks_hit,
				blks_read,
				local_blks_hit,
				local_blks_read,
				temp_blks_read,
				temp_blks_written,
				target,
				(void *)planstate);

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
 * Check if another session requested tracing for this backend.
 * If so, enable tracing. Called at the start of planner hook.
 */
static void
check_trace_request(void)
{
	int slot;

	if (ring_buffer_ctl == NULL)
		return;

	/* Find our slot based on our PID */
	slot = MyProcPid % MAX_TRACED_BACKENDS;

	/* Check if tracing was requested for us */
	if (pg_atomic_read_u32(&ring_buffer_ctl->trace_requests[slot].requested))
	{
		/* Clear the request flag */
		pg_atomic_write_u32(&ring_buffer_ctl->trace_requests[slot].requested, 0);

		/* Check if eBPF was already started externally */
		if (pg_atomic_read_u32(&ring_buffer_ctl->trace_requests[slot].ebpf_active))
		{
			/* Mark that eBPF is already running - don't start again */
			trace_state.ebpf_active = true;
			pg_atomic_write_u32(&ring_buffer_ctl->trace_requests[slot].ebpf_active, 0);
			elog(LOG, "pg_10046: trace enabled by request (eBPF already active)");
		}
		else
		{
			elog(LOG, "pg_10046: trace enabled by request from PID %d",
				 ring_buffer_ctl->trace_requests[slot].requester_pid);
		}

		ring_buffer_ctl->trace_requests[slot].requester_pid = 0;

		/* Enable tracing for this backend */
		pg10046_enabled = true;
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

	/* Check if another session requested tracing for us */
	check_trace_request();

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

			/* Only fsync if NOT using ring buffer */
			if (!(ring_buffer_ctl != NULL &&
				  pg_atomic_read_u32(&ring_buffer_ctl->worker_running) &&
				  my_backend_slot >= 0))
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
		/*
		 * By default, DON'T enable PostgreSQL's native instrumentation - it's too
		 * expensive. PostgreSQL's InstrStartNode/InstrStopNode add significant
		 * overhead even without INSTRUMENT_TIMER.
		 *
		 * If pg_10046.track_buffers is enabled, we use INSTRUMENT_BUFFERS | INSTRUMENT_ROWS
		 * to get per-node buffer stats. WARNING: This adds ~500% overhead!
		 */
		if (pg10046_track_buffers)
		{
			/* Enable expensive but detailed buffer tracking */
			int needed_instruments = INSTRUMENT_BUFFERS | INSTRUMENT_ROWS;
			if (queryDesc->instrument_options == 0)
				queryDesc->instrument_options = needed_instruments;
			else
				queryDesc->instrument_options |= needed_instruments;
		}

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

		/* Buffer all trace output during execution, flush once at query end.
		 * This bypasses expensive ring buffer operations (6 atomics + SetLatch per event).
		 */
		start_trace_buffering();

		write_trace("EXEC_START,%ld,%lu\n",
					trace_state.exec_start_time,
					trace_state.query_id);

		emit_node_mapping(queryDesc->planstate, NULL, 1);

		/* Start periodic sampling */
		setup_sampling_timer();

		/* Only fsync if NOT using ring buffer */
		if (!(ring_buffer_ctl != NULL &&
			  pg_atomic_read_u32(&ring_buffer_ctl->worker_running) &&
			  my_backend_slot >= 0))
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

		/* Flush all buffered trace output to ring buffer/file */
		flush_trace_buffer();

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
