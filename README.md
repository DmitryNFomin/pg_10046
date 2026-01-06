# pg_10046 - Oracle 10046-style Tracing for PostgreSQL

Real-time SQL tracing for PostgreSQL similar to Oracle's event 10046 trace. Captures query execution with per-node timing, IO attribution, and wait events.

## Features

- **Real-time node execution**: See when each plan node starts/stops with timing
- **IO attribution**: Know exactly which plan node caused each block read
- **Wait events**: Track wait events attributed to specific plan nodes
- **Query text capture**: SQL statement and execution context
- **Low overhead**: eBPF-based tracing with minimal performance impact

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      PostgreSQL Backend                         │
├─────────────────────────────────────────────────────────────────┤
│  ExecutorRun → ExecProcNode → InstrStartNode/InstrStopNode      │
│                     │                  │                        │
│                     ▼                  ▼                        │
│              mdread (IO)        WaitEventSetWait                │
└─────────────────────────────────────────────────────────────────┘
           │                    │                │
           ▼                    ▼                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    eBPF/bpftrace Probes                         │
│                                                                 │
│  • uprobe:InstrStartNode  - Node execution start                │
│  • uprobe:InstrStopNode   - Node execution end                  │
│  • uprobe:mdread          - Block read start                    │
│  • uretprobe:mdread       - Block read end with timing          │
│  • uprobe:WaitEventSetWait - Wait event tracking                │
└─────────────────────────────────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Trace Output File                           │
│                                                                 │
│  TIM,EVENT,NODE_ID,PARENT_ID,DETAIL                             │
│  12345,QUERY_START,0,0,sql=SELECT...                            │
│  12346,NODE_START,1,0,depth=1                                   │
│  12347,NODE_START,2,1,depth=2                                   │
│  12348,IO,2,0,rel=24626 blk=0 ela=271                           │
│  12349,NODE_STOP,2,1,ela=849                                    │
└─────────────────────────────────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────────────┐
│                    pg_10046_report.py                           │
│                                                                 │
│  Summary Report:                                                │
│    Node  Parent  Calls     Time      IO   IO Time               │
│       1       0      1     0 us       0      0 us               │
│       2       1  50345   4.06s     868  372 ms                  │
│                                                                 │
│  Timeline View:                                                 │
│    +732us   NODE_START  Node=1                                  │
│    +1.1ms   NODE_START  Node=2                                  │
│    +1.6ms   IO          Node=2 blk=0 ela=271us                  │
└─────────────────────────────────────────────────────────────────┘
```

## Requirements

- PostgreSQL 13+ with debug symbols (debuginfo package)
- Linux with eBPF support (kernel 4.9+)
- bpftrace installed
- Root access for eBPF tracing

## Quick Start

1. **Start the tracer** (as root):
```bash
sudo bpftrace poc/pg_trace_full.bt > /tmp/trace.out 2>&1 &
```

2. **Run your query** (with instrumentation enabled):
```sql
EXPLAIN ANALYZE SELECT * FROM your_table WHERE ...;
```

3. **Stop the tracer** (Ctrl+C or kill)

4. **Generate report**:
```bash
python3 tools/pg_10046_report.py /tmp/trace.out
python3 tools/pg_10046_report.py /tmp/trace.out --timeline  # Show event timeline
```

## Trace Format

CSV format: `TIMESTAMP,EVENT,NODE_ID,PARENT_ID,DETAIL`

| Event | Description |
|-------|-------------|
| QUERY_START | Query execution begins, includes SQL text |
| QUERY_END | Query execution ends |
| NODE_START | Plan node starts executing |
| NODE_STOP | Plan node finishes, includes elapsed time |
| IO | Block read, attributed to causing node |
| WAIT | Wait event, attributed to causing node |

## Node Attribution

The tracer maintains a per-thread node stack. When IO or wait events occur, they're attributed to the currently executing (innermost) node:

```
Aggregate (depth=1)     ← Active
  └─ SeqScan (depth=2)  ← Currently executing, IO attributed here
```

## Example Output

```
======================================================================
QUERY 1
======================================================================
SQL: EXPLAIN ANALYZE SELECT count(*), sum(length(data)) FROM io_test;

Total execution time: 15.16 s

======================================================================
NODE SUMMARY
======================================================================
  Node Parent    Calls         Time     IO      IO Time  Waits    Wait Time
----------------------------------------------------------------------
     1      0        1         0 us      0         0 us      0         0 us
     2      1    50345       4.06 s    868    372.04 ms      0         0 us

======================================================================
IO BREAKDOWN BY NODE
======================================================================
Node 2:
  Relation 24626: 868 blocks, 372.04 ms
```

## Files

```
pg_10046/
├── poc/
│   ├── pg_trace_full.bt      # Main bpftrace tracer
│   ├── 01_test_node_tracing.bt   # Test node events
│   ├── 02_test_wait_events.bt    # Test wait events
│   └── 03_test_io_tracing.bt     # Test IO tracing
├── tools/
│   └── pg_10046_report.py    # Report generator
├── extension/
│   ├── pg_10046.c            # Extension (SQL/binds/plan capture)
│   └── Makefile
└── README.md
```

## Comparison with Oracle 10046

| Feature | Oracle 10046 | pg_10046 |
|---------|--------------|----------|
| SQL text | Yes | Yes |
| Bind variables | Yes | Planned (via extension) |
| Execution plan | Yes | Planned (via extension) |
| Node timing | Yes | Yes |
| Wait events | Yes | Yes |
| IO attribution | No (session level) | Yes (per-node) |
| Implementation | Kernel tracing | eBPF |
| Overhead | Low | Low |

## Limitations

- Requires EXPLAIN ANALYZE to enable instrumentation
- Debug symbols needed for function names
- eBPF overhead on high-frequency queries
- Node names not captured (need extension integration)

## Future Work

1. **Extension integration**: Capture SQL text, bind variables, and plan text from extension, merge with eBPF trace
2. **Node type mapping**: Map node IDs to node types (SeqScan, IndexScan, etc.)
3. **Relation name lookup**: Map relation OIDs to table names
4. **Wait event decoding**: Decode wait event classes to human-readable names
5. **Continuous tracing**: Support long-running trace sessions with rotation
