/*
 * pg_10046_wrapper.c - Alternative approach using ExecProcNode wrapper
 *
 * CONCEPT: Instead of hooking InstrStartNode/StopNode (which aren't hookable),
 * we can replace each PlanState's ExecProcNodeReal with our own wrapper.
 *
 * How it works:
 * 1. In ExecutorStart hook (after standard_ExecutorStart), walk the plan tree
 * 2. For each node, save original ExecProcNodeReal
 * 3. Replace ExecProcNodeReal with our wrapper
 * 4. Our wrapper logs before/after calling the original
 *
 * The standard flow with instrumentation is:
 *   ExecProcNode(node)
 *     -> ExecProcNodeInstr(node)
 *          -> InstrStartNode(node->instrument)
 *          -> node->ExecProcNodeReal(node)   <-- We replace THIS
 *          -> InstrStopNode(node->instrument, tuples)
 *
 * By replacing ExecProcNodeReal, our wrapper gets called in the middle
 * of the instrumentation, so we can add our own logging.
 *
 * PROS:
 * - Pure extension, no eBPF needed
 * - Works without debug symbols
 *
 * CONS:
 * - More overhead than eBPF (extra function calls)
 * - Complex to maintain across PG versions
 * - Doesn't capture the EXACT timing that InstrStartNode/StopNode see
 * - We see timing INSIDE the instrumentation, not including it
 *
 * Copyright (c) 2024
 */

#include "postgres.h"
#include "executor/executor.h"
#include "executor/instrument.h"
#include "nodes/execnodes.h"
#include "miscadmin.h"
#include "utils/memutils.h"

/* Maximum plan tree depth we support */
#define MAX_PLAN_NODES 256

/* Per-node wrapper state */
typedef struct NodeWrapper
{
    PlanState      *node;
    ExecProcNodeMtd original_func;  /* Saved ExecProcNodeReal */
    int             node_id;
} NodeWrapper;

/* Global state for current query */
static NodeWrapper node_wrappers[MAX_PLAN_NODES];
static int num_wrapped_nodes = 0;
static int current_depth = 0;
static int trace_fd = -1;

/* Forward declarations */
static TupleTableSlot *wrapped_exec_proc_node(PlanState *node);
static void wrap_plan_tree(PlanState *planstate, int depth);
static void unwrap_plan_tree(void);
static void write_node_event(const char *event, int node_id, int depth, int64 ela_us);

/*
 * Find wrapper info for a node
 */
static NodeWrapper *
find_wrapper(PlanState *node)
{
    int i;
    for (i = 0; i < num_wrapped_nodes; i++)
    {
        if (node_wrappers[i].node == node)
            return &node_wrappers[i];
    }
    return NULL;
}

/*
 * Our wrapper function that replaces ExecProcNodeReal
 */
static TupleTableSlot *
wrapped_exec_proc_node(PlanState *node)
{
    NodeWrapper    *wrapper;
    TupleTableSlot *result;
    instr_time      start_time;
    instr_time      end_time;
    int64           ela_us;

    wrapper = find_wrapper(node);
    if (!wrapper)
    {
        /* Shouldn't happen, but fall back to standard */
        elog(WARNING, "pg_10046: wrapper not found for node");
        return ExecProcNode(node);
    }

    /* Log NODE_START */
    current_depth++;
    INSTR_TIME_SET_CURRENT(start_time);
    write_node_event("NODE_START", wrapper->node_id, current_depth, 0);

    /* Call original execution function */
    result = wrapper->original_func(node);

    /* Log NODE_STOP with timing */
    INSTR_TIME_SET_CURRENT(end_time);
    INSTR_TIME_SUBTRACT(end_time, start_time);
    ela_us = INSTR_TIME_GET_MICROSEC(end_time);
    write_node_event("NODE_STOP", wrapper->node_id, current_depth, ela_us);
    current_depth--;

    return result;
}

/*
 * Walk plan tree and wrap each node's ExecProcNodeReal
 */
static void
wrap_plan_tree(PlanState *planstate, int depth)
{
    if (planstate == NULL)
        return;

    if (num_wrapped_nodes >= MAX_PLAN_NODES)
    {
        elog(WARNING, "pg_10046: too many plan nodes, some won't be traced");
        return;
    }

    /* Save original and replace with our wrapper */
    node_wrappers[num_wrapped_nodes].node = planstate;
    node_wrappers[num_wrapped_nodes].original_func = planstate->ExecProcNodeReal;
    node_wrappers[num_wrapped_nodes].node_id = num_wrapped_nodes + 1;
    num_wrapped_nodes++;

    /* Replace the execution function */
    planstate->ExecProcNodeReal = wrapped_exec_proc_node;

    /* Recurse to children */
    wrap_plan_tree(planstate->lefttree, depth + 1);
    wrap_plan_tree(planstate->righttree, depth + 1);

    /* Handle special node types with additional children */
    switch (nodeTag(planstate))
    {
        case T_AppendState:
            {
                AppendState *as = (AppendState *) planstate;
                int i;
                for (i = 0; i < as->as_nplans; i++)
                    wrap_plan_tree(as->appendplans[i], depth + 1);
            }
            break;

        case T_MergeAppendState:
            {
                MergeAppendState *ms = (MergeAppendState *) planstate;
                int i;
                for (i = 0; i < ms->ms_nplans; i++)
                    wrap_plan_tree(ms->mergeplans[i], depth + 1);
            }
            break;

        case T_SubqueryScanState:
            {
                SubqueryScanState *ss = (SubqueryScanState *) planstate;
                wrap_plan_tree(ss->subplan, depth + 1);
            }
            break;

        default:
            break;
    }
}

/*
 * Restore original functions (called in ExecutorEnd)
 */
static void
unwrap_plan_tree(void)
{
    int i;

    for (i = 0; i < num_wrapped_nodes; i++)
    {
        if (node_wrappers[i].node)
            node_wrappers[i].node->ExecProcNodeReal = node_wrappers[i].original_func;
    }

    num_wrapped_nodes = 0;
    current_depth = 0;
}

/*
 * Write node event to trace file
 */
static void
write_node_event(const char *event, int node_id, int depth, int64 ela_us)
{
    char buf[256];
    int len;

    if (trace_fd < 0)
        return;

    if (ela_us > 0)
        len = snprintf(buf, sizeof(buf), "%s id=%d depth=%d ela=%ld us\n",
                       event, node_id, depth, ela_us);
    else
        len = snprintf(buf, sizeof(buf), "%s id=%d depth=%d\n",
                       event, node_id, depth);

    if (len > 0)
        (void) write(trace_fd, buf, len);
}

/*
 * IMPORTANT NOTES:
 *
 * 1. This approach wraps ExecProcNodeReal, which is called INSIDE
 *    ExecProcNodeInstr, between InstrStartNode and InstrStopNode.
 *    So we're adding our own timing on top of PostgreSQL's.
 *
 * 2. For accurate timing comparable to eBPF, we'd need to:
 *    - Either patch PostgreSQL to add hooks in InstrStartNode/StopNode
 *    - Or use LD_PRELOAD to intercept the functions
 *    - Or use eBPF (cleanest approach)
 *
 * 3. The overhead of this wrapper approach is:
 *    - Function pointer lookup (find_wrapper)
 *    - Extra timing calls (INSTR_TIME_SET_CURRENT)
 *    - Write to trace file (can be deferred to ring buffer)
 *
 * 4. This is a PROOF OF CONCEPT. For production, consider:
 *    - Using a ring buffer instead of direct file writes
 *    - Batching events
 *    - Making the wrapper static per-node to avoid lookup
 */
