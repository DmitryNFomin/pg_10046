# PostgreSQL Oracle 10046-Style Tracing: Approach Evaluation

## Requirements Summary

| # | Requirement | Description |
|---|-------------|-------------|
| 1 | SQL query text | Full query string |
| 2 | Bind variables | Parameter values with types |
| 3 | Execution plan text | EXPLAIN-style output |
| 4 | **Real-time plan node progress** | As nodes start/end, with stats |
| 5 | Wait events | What the backend waits on during execution |
| 6 | CPU used | Time spent on CPU |
| 7 | IO calls with file info | File name, block/offset, timing |
| 8 | Rows and buffers stats | Per-node statistics |

**Requirement #4 is the key differentiator** - Oracle 10046 shows plan node activity *as it happens*, not just at the end.

---

## How PostgreSQL Instrumentation Works

When `instrument_options` is set (e.g., `INSTRUMENT_ALL`), PostgreSQL:

1. Allocates `Instrumentation` struct for each `PlanState` node
2. Wraps node execution with `ExecProcNodeInstr()` which calls:
   - `InstrStartNode()` - marks start time, captures buffer baseline
   - `node->ExecProcNodeReal()` - actual execution
   - `InstrStopNode()` - accumulates time, buffer diff, tuple count

**Key insight**: `InstrStartNode`/`InstrStopNode` are called in real-time during execution. If we can capture these events, we get real-time plan progress.

---

## Approach 1: Pure Extension

### Architecture
```
┌─────────────────────────────────────────────────┐
│                  Extension                       │
│  ExecutorStart: enable INSTRUMENT_ALL            │
│  ExecutorRun: periodically sample wait events    │
│  ExecutorEnd: walk plan tree, write stats        │
└─────────────────────────────────────────────────┘
```

### What It Can Do
| Requirement | Status | How |
|-------------|--------|-----|
| SQL text | ✅ | `queryDesc->sourceText` |
| Bind variables | ✅ | `queryDesc->params` |
| Execution plan | ✅ | `ExplainPrintPlan()` |
| Real-time node progress | ❌ | **Cannot hook InstrStartNode/StopNode** |
| Wait events | ⚠️ | Timer sampling (10ms granularity) |
| CPU | ✅ | `Instrumentation.total` |
| IO file info | ❌ | Only buffer counts, no file/block |
| Rows/buffers | ✅ | `Instrumentation.ntuples`, `bufusage` |

### Limitations
1. **Cannot intercept `InstrStartNode`/`InstrStopNode`** from extension - these are internal functions
2. Wait event sampling via timer is probabilistic - can miss short waits
3. No per-IO-call timing - only aggregate `blk_read_time`
4. No file/block information on IO operations

### Your Idea: Periodic Instrumentation Dump
You suggested reading `Instrumentation` from backend every X ms. This is possible but:
- Signal handlers (SIGALRM) are limited in what they can do safely
- Walking plan tree in signal handler is risky
- Still doesn't give you "node started" events, only "current accumulated stats"

**Verdict**: Good for post-mortem analysis, **cannot meet requirement #4**.

---

## Approach 2: Pure eBPF

### Architecture
```
┌─────────────────────────────────────────────────┐
│              eBPF Program (uprobes)              │
│  InstrStartNode → NODE_START event               │
│  InstrStopNode  → NODE_STOP event + stats        │
│  WaitEventSetWait → WAIT event with timing       │
│  mdread → IO event with RelFileNode              │
│  standard_ExecutorRun → query text capture       │
└─────────────────────────────────────────────────┘
          │ Ring buffer
          ▼
┌─────────────────────────────────────────────────┐
│           Userspace Collector                    │
│  Parse events, write trace file                  │
└─────────────────────────────────────────────────┘
```

### What It Can Do
| Requirement | Status | How |
|-------------|--------|-----|
| SQL text | ✅ | Read `QueryDesc->sourceText` in ExecutorRun |
| Bind variables | ⚠️ | Complex - need type-aware Datum decoding |
| Execution plan | ⚠️ | Must reconstruct from node events |
| Real-time node progress | ✅ | **Hook InstrStartNode/StopNode** |
| Wait events | ✅ | Hook WaitEventSetWait with timing |
| CPU | ✅ | Timestamp diff in InstrStopNode |
| IO file info | ✅ | Hook mdread, read RelFileNode |
| Rows/buffers | ✅ | Read Instrumentation struct |

### Key uprobes

```c
// Real-time node execution
uprobe:postgres:InstrStartNode     // arg0 = Instrumentation*
uprobe:postgres:InstrStopNode      // arg0 = Instrumentation*, arg1 = nTuples

// Wait events (exact timing)
uprobe:postgres:WaitEventSetWait   // arg4 = wait_event_info
uretprobe:postgres:WaitEventSetWait

// IO with file info
uprobe:postgres:mdread             // arg0 = SMgrRelation (contains RelFileNode)
uretprobe:postgres:mdread
```

### Limitations
1. Requires debug symbols
2. Bind variable decoding is complex (Datum types vary)
3. Execution plan text must be reconstructed from nodes
4. eBPF string handling limited (~256 bytes per read)
5. Higher deployment complexity (root, BCC/bpftrace)

**Verdict**: **Can meet requirement #4**, but #2 and #3 are harder.

---

## Approach 3: Hybrid (Recommended)

### Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                    pg_10046 Extension                        │
│  ExecutorStart:                                              │
│    - Enable INSTRUMENT_ALL                                   │
│    - Write PARSING header (SQL, binds)                       │
│    - Signal eBPF collector to start                          │
│  ExecutorEnd:                                                │
│    - Write execution plan text                               │
│    - Write final summary stats                               │
│    - Signal eBPF collector to stop                           │
└─────────────────────────────────────────────────────────────┘
                              │
                    Shared memory / signal
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    eBPF Collector                            │
│  Uprobes for PID:                                            │
│    - InstrStartNode → NODE_START                             │
│    - InstrStopNode  → NODE_STOP + per-node stats             │
│    - WaitEventSetWait → WAIT events                          │
│    - mdread → IO events with file/block                      │
│  Output: Ring buffer → merged trace file                     │
└─────────────────────────────────────────────────────────────┘
```

### What It Can Do
| Requirement | Status | How |
|-------------|--------|-----|
| SQL text | ✅ | Extension: `queryDesc->sourceText` |
| Bind variables | ✅ | Extension: decode params in-process |
| Execution plan | ✅ | Extension: `ExplainPrintPlan()` |
| Real-time node progress | ✅ | eBPF: InstrStartNode/StopNode |
| Wait events | ✅ | eBPF: exact timing via WaitEventSetWait |
| CPU | ✅ | Both: Instrumentation + timestamps |
| IO file info | ✅ | eBPF: mdread with RelFileNode |
| Rows/buffers | ✅ | Both: Instrumentation struct |

### Benefits
- Extension handles complex in-process data (binds, plan text)
- eBPF handles real-time events (node progress, waits, IO)
- Clean separation of concerns
- Extension can control when eBPF tracing is active

**Verdict**: **Best approach - meets all requirements**.

---

## Comparison Matrix

| Feature | Extension | eBPF | Hybrid |
|---------|-----------|------|--------|
| SQL text | ✅ | ✅ | ✅ |
| Bind variables | ✅ | ⚠️ | ✅ |
| Plan text | ✅ | ⚠️ | ✅ |
| **Real-time nodes** | ❌ | ✅ | ✅ |
| Wait events exact | ⚠️ | ✅ | ✅ |
| IO file/block info | ❌ | ✅ | ✅ |
| Deployment ease | ✅ | ⚠️ | ⚠️ |
| No debug symbols | ✅ | ❌ | ❌ |

---

## PoC Recommendation

For your VM with PG13 and debug symbols, I recommend testing in this order:

### Phase 1: Verify eBPF can capture real-time node events
Test that we can see InstrStartNode/InstrStopNode with timing and stats.

### Phase 2: Verify wait event tracing
Test WaitEventSetWait capture with exact timing.

### Phase 3: Verify IO tracing with file info
Test mdread capture with RelFileNode (OIDs).

### Phase 4: Build minimal extension
Extension that enables instrumentation and writes SQL/binds/plan to trace file.

### Phase 5: Integrate
Merge eBPF events with extension output into unified Oracle 10046-style trace.

---

## Output Format (Oracle 10046 style)

```
*** TRACE FILE ***
*** PID: 12345 ***
*** 2024-12-30 10:00:00.000 ***

PARSING IN CURSOR #1 len=42 dep=0 tim=123456789
SELECT * FROM orders WHERE customer_id = $1
END OF STMT

BINDS #1:
 Bind#0 val=42 type=int4

EXEC #1:c=1234,e=5678,p=10,cr=100,cu=5,rows=50

PLAN #1:
Seq Scan on orders  (cost=0.00..100.00 rows=50 width=100)
  Filter: (customer_id = 42)

NODE_START #1 id=1 type=SeqScan tim=123456789
WAIT #1 nam='IO:DataFileRead' ela=1234
IO #1 rel=16384 blk=0 ela=1200
IO #1 rel=16384 blk=1 ela=1100
NODE_STOP #1 id=1 rows=50 buf_hit=98 buf_read=2 tim=123460000

STAT #1 id=1 cnt=50 op='Seq Scan (actual time=0.010..3.211 rows=50 loops=1)'
  Buffers: shared hit=98 read=2
```
