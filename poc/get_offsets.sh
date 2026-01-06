#!/bin/bash
#
# get_offsets.sh - Extract PostgreSQL struct offsets for eBPF tracing
#
# Usage: ./get_offsets.sh /path/to/postgres
#

PG_BIN="${1:-/usr/lib/postgresql/13/bin/postgres}"

if [ ! -f "$PG_BIN" ]; then
    echo "Error: PostgreSQL binary not found at $PG_BIN"
    echo "Usage: $0 /path/to/postgres"
    exit 1
fi

echo "=== PostgreSQL Struct Offsets for eBPF Tracing ==="
echo "Binary: $PG_BIN"
echo ""

# Check for debug symbols
if ! nm "$PG_BIN" 2>/dev/null | grep -q "InstrStartNode"; then
    echo "Warning: Debug symbols may not be present. Install *-dbgsym package."
fi

echo "=== QueryDesc ==="
gdb -batch -ex 'p sizeof(struct QueryDesc)' "$PG_BIN" 2>/dev/null | grep '\$'
gdb -batch -ex 'p &((struct QueryDesc*)0)->sourceText' "$PG_BIN" 2>/dev/null | grep '\$'
gdb -batch -ex 'p &((struct QueryDesc*)0)->params' "$PG_BIN" 2>/dev/null | grep '\$'
gdb -batch -ex 'p &((struct QueryDesc*)0)->planstate' "$PG_BIN" 2>/dev/null | grep '\$'
gdb -batch -ex 'p &((struct QueryDesc*)0)->instrument_options' "$PG_BIN" 2>/dev/null | grep '\$'

echo ""
echo "=== Instrumentation ==="
gdb -batch -ex 'p sizeof(struct Instrumentation)' "$PG_BIN" 2>/dev/null | grep '\$'
gdb -batch -ex 'p &((struct Instrumentation*)0)->running' "$PG_BIN" 2>/dev/null | grep '\$'
gdb -batch -ex 'p &((struct Instrumentation*)0)->startup' "$PG_BIN" 2>/dev/null | grep '\$'
gdb -batch -ex 'p &((struct Instrumentation*)0)->total' "$PG_BIN" 2>/dev/null | grep '\$'
gdb -batch -ex 'p &((struct Instrumentation*)0)->ntuples' "$PG_BIN" 2>/dev/null | grep '\$'
gdb -batch -ex 'p &((struct Instrumentation*)0)->nloops' "$PG_BIN" 2>/dev/null | grep '\$'
gdb -batch -ex 'p &((struct Instrumentation*)0)->bufusage' "$PG_BIN" 2>/dev/null | grep '\$'

echo ""
echo "=== BufferUsage ==="
gdb -batch -ex 'p sizeof(struct BufferUsage)' "$PG_BIN" 2>/dev/null | grep '\$'
gdb -batch -ex 'p &((struct BufferUsage*)0)->shared_blks_hit' "$PG_BIN" 2>/dev/null | grep '\$'
gdb -batch -ex 'p &((struct BufferUsage*)0)->shared_blks_read' "$PG_BIN" 2>/dev/null | grep '\$'
gdb -batch -ex 'p &((struct BufferUsage*)0)->blk_read_time' "$PG_BIN" 2>/dev/null | grep '\$'

echo ""
echo "=== PlanState ==="
gdb -batch -ex 'p &((struct PlanState*)0)->instrument' "$PG_BIN" 2>/dev/null | grep '\$'
gdb -batch -ex 'p &((struct PlanState*)0)->type' "$PG_BIN" 2>/dev/null | grep '\$'

echo ""
echo "=== SMgrRelationData (for IO tracing) ==="
gdb -batch -ex 'p &((struct SMgrRelationData*)0)->smgr_rnode' "$PG_BIN" 2>/dev/null | grep '\$'
# RelFileNodeBackend.node is at offset 0 within smgr_rnode
# RelFileNode: spcNode(0), dbNode(4), relNode(8)

echo ""
echo "=== PGPROC (for wait events) ==="
gdb -batch -ex 'p &((struct PGPROC*)0)->wait_event_info' "$PG_BIN" 2>/dev/null | grep '\$'

echo ""
echo "=== Function symbols (verify they're available) ==="
nm -C "$PG_BIN" 2>/dev/null | grep -E "(InstrStartNode|InstrStopNode|WaitEventSetWait|mdread|standard_ExecutorRun)" | head -10

echo ""
echo "Done. Use these offsets in your eBPF scripts."
