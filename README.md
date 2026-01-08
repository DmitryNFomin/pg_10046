# pg_10046 - Oracle 10046-style SQL Tracing for PostgreSQL

Real-time SQL tracing for PostgreSQL inspired by Oracle's event 10046 trace. Captures complete query execution details including SQL text, bind variables, execution plans, per-node timing, IO operations, and wait events.

## Features

- **SQL and Bind Variable Capture**: Full query text with parameter values at planning time
- **Execution Plan Output**: Complete plan tree with cost estimates and node types
- **Per-Node Execution Tracking**: NODE_START/NODE_END events with precise timing
- **Periodic Wait Event Sampling**: Configurable interval sampling during execution
- **IO Attribution via eBPF**: Block-level IO tracking attributed to specific plan nodes
- **CPU Scheduling Tracking**: On-CPU/off-CPU time via eBPF probes
- **Ring Buffer Architecture**: Low-latency trace writing with background worker (like Oracle's DIAG process)
- **Buffer Usage Statistics**: Per-node buffer hit/read counts

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         PostgreSQL Backend                               │
├─────────────────────────────────────────────────────────────────────────┤
│  Planner Hook          Executor Hooks           Timeout Handler          │
│      │                      │                        │                   │
│      ▼                      ▼                        ▼                   │
│  SQL/Binds/Plan     NODE_START/END            SAMPLE events              │
│                                                                          │
└──────────────────────────────┬───────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    Shared Memory Ring Buffer (32MB)                      │
│                                                                          │
│  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐        Lock-free atomic ops    │
│  │Slot │ │Slot │ │Slot │ │Slot │ │Slot │ ...    65,536 slots            │
│  └─────┘ └─────┘ └─────┘ └─────┘ └─────┘                                 │
└──────────────────────────────┬───────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│              Background Worker: pg_10046 trace writer                    │
│                                                                          │
│  • Reads events from ring buffer                                         │
│  • Maintains file descriptor cache per backend                           │
│  • Batched writes at configurable interval (default 1s)                  │
│  • Minimal impact on query latency                                       │
└──────────────────────────────┬───────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    Trace Files: /tmp/pg_10046_<pid>_<ts>.trc             │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                     Optional: eBPF Daemon (pg_10046d)                    │
├─────────────────────────────────────────────────────────────────────────┤
│  Global bpftrace probes:                                                 │
│  • mdread/mdwrite     - Block IO with timing                             │
│  • block:block_rq_*   - Distinguish disk vs OS cache                     │
│  • sched:sched_switch - CPU scheduling (on/off CPU)                      │
│  • ReadBufferExtended - Buffer request attribution                       │
│                                                                          │
│  Output: /tmp/pg_10046_ebpf_<pid>_<ts>.trc                               │
└─────────────────────────────────────────────────────────────────────────┘
```

## Requirements

- PostgreSQL 13+ (tested on 13, should work on 14+)
- Linux with eBPF support (kernel 4.9+) for IO tracing
- bpftrace installed (for eBPF features)
- PostgreSQL debug symbols (debuginfo package) for eBPF
- Root access for eBPF tracing

## Installation

### 1. Build the Extension

```bash
cd extension
make
sudo make install
```

### 2. Configure PostgreSQL

Add to `postgresql.conf`:

```
shared_preload_libraries = 'pg_10046'

# Optional: customize settings
pg_10046.ring_buffer_mb = 32           # Ring buffer size (1-1024 MB)
pg_10046.flush_interval_ms = 1000      # Background flush interval
pg_10046.sample_interval_ms = 10       # Wait event sampling interval
pg_10046.trace_dir = '/tmp'            # Trace file directory
```

Restart PostgreSQL:

```bash
sudo systemctl restart postgresql-13
```

### 3. Install eBPF Daemon (Optional)

For IO and CPU tracing:

```bash
sudo cp tools/pg_10046d.py /usr/local/bin/
sudo cp tools/pg_10046_ebpf.sh /usr/local/bin/

# Start the daemon
sudo python3 /usr/local/bin/pg_10046d.py &
```

## Usage

### Enable Tracing for a Session

```sql
-- Enable tracing
SET pg_10046.enabled = true;

-- Optional: enable eBPF IO tracing
SET pg_10046.ebpf_enabled = true;

-- Run your queries
SELECT count(*) FROM large_table WHERE status = 'active';

-- Tracing continues until session ends or disabled
SET pg_10046.enabled = false;
```

### View Trace Files

```bash
# Extension trace (SQL, plans, node events)
cat /tmp/pg_10046_<pid>_<timestamp>.trc

# eBPF trace (IO, CPU events)
cat /tmp/pg_10046_ebpf_<pid>_<timestamp>.trc
```

## Configuration Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `pg_10046.enabled` | off | Enable tracing for session |
| `pg_10046.ebpf_enabled` | off | Enable eBPF IO/CPU tracing |
| `pg_10046.trace_dir` | /tmp | Directory for trace files |
| `pg_10046.ring_buffer_mb` | 32 | Shared memory ring buffer size (MB) |
| `pg_10046.flush_interval_ms` | 1000 | Background worker flush interval (ms) |
| `pg_10046.sample_interval_ms` | 10 | Wait event sampling interval (ms) |
| `pg_10046.daemon_socket` | /var/run/pg_10046.sock | eBPF daemon socket path |

## Trace File Format

### Extension Trace Events

```
# Header
# PG_10046 TRACE
# TRACE_ID: 12345_20260108120000
# TRACE_UUID: abc123-def456-...
# PID: 12345
# RING_BUFFER_ACTIVE: true

# Query start with SQL
QUERY_START,<timestamp>,<query_id>,sql=<query_text>

# Bind variables
BIND,<timestamp>,<param_num>,type=<type>,value=<value>

# Execution plan
PLAN_START
PLAN,<node_id>,<parent_id>,<depth>,<node_type>,<rows>,<cost>,<target>
PLAN_END
PLAN_TIME,<microseconds>

# Execution events
EXEC_START,<timestamp>,<query_id>
NODE_MAP,<node_ptr>,<parent_ptr>,<node_type>,<node_id>,<target>
NODE_START,<timestamp>,<node_ptr>,<node_type>,<target>
NODE_END,<timestamp>,<node_ptr>,<node_type>,tuples=N,blks_hit=N,blks_read=N,time_us=N,<target>

# Periodic samples during execution
SAMPLE,<timestamp>,<node_ptr>,<wait_event>,<sample_num>,<tuples>,<blks_hit>,<blks_read>

# Final statistics
STATS_START
STAT,<node_id>,<parent_id>,<depth>,<type>,<rows>,<loops>,<workers>,<total_ms>,<self_ms>,<blks_hit>,<blks_read>,...
STATS_END
EXEC_END,<timestamp>,<query_id>,ela=<total_microseconds>
```

### eBPF Trace Events

```
# IO events (disk reads/writes)
<timestamp>,IO_READ,<node_ptr>,<spc>,<db>,<rel>,<fork>,<seg>,<blk>,<ela_us>,<disk>,<blk_ela_us>
<timestamp>,IO_WRITE,<node_ptr>,<spc>,<db>,<rel>,<fork>,<seg>,<blk>,<ela_us>,<disk>,<blk_ela_us>

# CPU scheduling
<timestamp>,CPU_OFF,<node_ptr>,<on_cpu_duration_us>
<timestamp>,CPU_ON,<node_ptr>,<off_cpu_duration_us>

# Buffer requests
<timestamp>,BUF_REQ,<node_ptr>,gap_from_node=<us>
```

## Example Output

```
# PG_10046 TRACE
# TRACE_ID: 364958_20260108090730
# PID: 364958
# RING_BUFFER_MB: 32
# RING_BUFFER_ACTIVE: true
#
QUERY_START,825241700000,1,sql=SELECT count(*) FROM io_test WHERE id < 1000;
PLAN_START
PLAN,1,0,1,Aggregate,1,1175.00,
PLAN,2,1,2,SeqScan,3996,1165.00,io_test
PLAN_END
PLAN_TIME,1523
EXEC_START,825241710000,1
NODE_MAP,0x26769f78,(nil),Aggregate,1,
NODE_MAP,0x2675c118,0x26769f78,SeqScan,2,io_test
SAMPLING_START,interval_ms=10
NODE_START,825241715000,0x2675c118,SeqScan,io_test
SAMPLE,825241725891,0x2675c118,0x00000000,1,34,25,11
SAMPLE,825241737261,0x2675c118,0x00000000,2,275,234,43
...
NODE_END,825241900000,0x2675c118,SeqScan,tuples=3996,blks_hit=1200,blks_read=544,time_us=185000,io_test
NODE_END,825241900500,0x26769f78,Aggregate,tuples=1,blks_hit=1200,blks_read=544,time_us=190500,
SAMPLING_END,samples=17
STATS_START
STAT,1,0,1,Aggregate,1,1,0,190.500,5.000,1200,544,0,0,0,0,,0x26769f78
STAT,2,1,2,SeqScan,3996,1,0,185.000,185.000,1200,544,0,0,0,0,io_test,0x2675c118
STATS_END
EXEC_END,825241901000,1,ela=191000
```

## Comparison with Oracle 10046

| Feature | Oracle 10046 | pg_10046 |
|---------|--------------|----------|
| SQL text | Yes | Yes |
| Bind variables | Yes | Yes |
| Execution plan | Yes | Yes |
| Node timing | Yes | Yes |
| Wait events | Yes | Yes (sampled) |
| IO attribution | Session level | Per-node (via eBPF) |
| CPU time | Yes | Yes (via eBPF) |
| Ring buffer | Yes (PGA) | Yes (shared memory) |
| Background writer | DIAG process | Background worker |
| Implementation | Kernel tracing | Extension + eBPF |

## Files

```
pg_10046/
├── extension/
│   ├── pg_10046.c           # Main PostgreSQL extension
│   ├── pg_10046.control     # Extension metadata
│   ├── pg_10046--1.0.sql    # Extension SQL
│   └── Makefile             # Build configuration
├── tools/
│   ├── pg_10046d.py         # eBPF daemon (manages bpftrace)
│   ├── pg_10046_ebpf.sh     # Manual eBPF start/stop script
│   ├── pg_10046_merge.py    # Merge extension + eBPF traces
│   └── pg_10046_report.py   # Generate trace reports
├── .gitignore
└── README.md
```

## Performance Considerations

- **Ring Buffer**: 32MB default handles high-throughput workloads without drops
- **Background Worker**: Batched writes minimize query latency impact
- **eBPF Overhead**: ~1-5% overhead when eBPF tracing enabled
- **Sampling**: Configurable interval balances detail vs overhead
- **Signal Safety**: SAMPLE events write directly to file for safety

## Limitations

- Requires `shared_preload_libraries` configuration (server restart)
- eBPF features require root access and debug symbols
- Node names require instrumentation (use EXPLAIN ANALYZE or pg_10046)
- SAMPLE events may appear out of order in high-throughput traces (signal safety)

## Troubleshooting

### No trace file created
- Check `pg_10046.enabled` is `true`
- Verify trace directory exists and is writable
- Check PostgreSQL logs for errors

### Missing eBPF events
- Verify pg_10046d daemon is running: `pgrep -f pg_10046d`
- Check daemon socket exists: `ls -la /var/run/pg_10046.sock`
- Verify bpftrace is installed: `which bpftrace`
- Check for eBPF errors in `/tmp/pg_10046d.log`

### Background worker not running
- Verify `shared_preload_libraries = 'pg_10046'` in postgresql.conf
- Check `ps aux | grep 'trace writer'`
- Review PostgreSQL logs for startup errors

## License

PostgreSQL License

## Contributing

Contributions welcome! Please submit issues and pull requests on GitHub.

## Acknowledgments

Inspired by Oracle's 10046 event tracing and the need for detailed PostgreSQL query diagnostics.
