# PostgreSQL 10046 Tracer - Proof of Concept

This directory contains PoC scripts for Oracle 10046-style tracing in PostgreSQL.

## Prerequisites

1. **PostgreSQL with debug symbols**
   ```bash
   # Ubuntu/Debian
   apt install postgresql-13-dbgsym

   # RHEL/Oracle Linux
   debuginfo-install postgresql13-server
   ```

2. **eBPF tools**
   ```bash
   # Ubuntu/Debian
   apt install bpftrace bpfcc-tools python3-bpfcc

   # RHEL/Oracle Linux
   dnf install bpftrace bcc-tools python3-bcc
   ```

3. **Root privileges** (required for eBPF)

## Verify Setup

Check that PostgreSQL functions are traceable:
```bash
sudo bpftrace -l 'uprobe:/usr/lib/postgresql/13/bin/postgres:*' | wc -l
# Should show thousands of functions

sudo bpftrace -l 'uprobe:/usr/lib/postgresql/13/bin/postgres:InstrStartNode'
# Should show the function
```

## PoC Scripts

### 1. Test Node Tracing (01_test_node_tracing.bt)

Tests if we can capture real-time plan node execution:
```bash
# Get a backend PID
psql -c "SELECT pg_backend_pid()"

# In another terminal
sudo bpftrace poc/01_test_node_tracing.bt -p <backend_pid>

# Run a query with instrumentation (enable auto_explain first)
```

### 2. Test Wait Events (02_test_wait_events.bt)

Tests wait event capture with timing:
```bash
sudo bpftrace poc/02_test_wait_events.bt -p <backend_pid>

# Run queries that cause waits (locks, IO, etc.)
```

### 3. Test IO Tracing (03_test_io_tracing.bt)

Tests IO capture with file/block info:
```bash
sudo bpftrace poc/03_test_io_tracing.bt -p <backend_pid>

# Run queries that read data (after flushing cache)
```

### 4. Full Combined Trace (04_full_trace.bt)

Combined tracer producing Oracle 10046-style output:
```bash
sudo bpftrace poc/04_full_trace.bt -p <backend_pid>
```

### 5. Python BCC Tracer (pg_tracer.py)

More advanced tracer using BCC with output to file:
```bash
sudo python3 poc/pg_tracer.py --pid <backend_pid> --output /tmp/trace.trc
```

## Adjusting Struct Offsets

The offsets in these scripts are for PostgreSQL 13 on ARM64. You may need to adjust them for your platform.

Get offsets using gdb:
```bash
# QueryDesc->sourceText offset
gdb -batch -ex 'p &((struct QueryDesc*)0)->sourceText' /usr/lib/postgresql/13/bin/postgres

# Instrumentation struct size
gdb -batch -ex 'p sizeof(struct Instrumentation)' /usr/lib/postgresql/13/bin/postgres

# Example offsets for PG13:
# QueryDesc.sourceText: 0x10 (16)
# Instrumentation.ntuples: 0xD0 (208)
# Instrumentation.bufusage: 0xF8 (248)
```

## Expected Output

### Node Tracing
```
NODE_START depth=1 tim=123456789
NODE_START depth=2 tim=123456800
NODE_STOP  depth=2 ela=1234 us
NODE_STOP  depth=1 ela=5678 us
```

### Wait Events
```
WAIT class=0x0a (IO) id=0x000001 ela=1500 us
WAIT class=0x01 (LWLock) id=0x000005 ela=50 us
```

### IO
```
IO rel=16384 blk=0 ela=1200 us
IO rel=16384 blk=1 ela=1100 us
```

### Full Trace
```
*** PG_10046 TRACE ***
*** PID: 12345 ***

PARSING IN CURSOR #1 tim=123456789
SELECT * FROM test WHERE id > 100
END OF STMT

NODE_START #1 depth=1 tim=123456800
WAIT #1 class=IO id=0x000001 ela=1500 us
IO #1 rel=16384 blk=0 ela=1200 us
NODE_STOP  #1 depth=1 ela=3000 us

EXEC #1 e=3500 us
```

## Troubleshooting

### "Failed to find function" error
Debug symbols may not be installed or the function name changed.
Check with:
```bash
nm -C /usr/lib/postgresql/13/bin/postgres | grep InstrStartNode
```

### No events captured
Ensure instrumentation is enabled. Either:
1. Use `auto_explain` with `log_analyze = on`
2. Use `EXPLAIN ANALYZE` explicitly
3. Extension sets `queryDesc->instrument_options |= INSTRUMENT_ALL`

### Wrong offsets causing garbage data
Verify offsets match your PostgreSQL build:
```bash
gdb -batch -ex 'ptype struct QueryDesc' /usr/lib/postgresql/13/bin/postgres
```

## Next Steps

After verifying these PoCs work:

1. **Build extension** that enables instrumentation and writes SQL/binds/plan
2. **Integrate eBPF events** with extension output
3. **Create report tool** to parse trace files (like Oracle tkprof)
