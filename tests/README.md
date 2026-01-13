# pg_10046 Test Framework

Comprehensive test suite for validating pg_10046 trace correctness and performance.

**145 tests** covering trace correctness, node tracking, eBPF/IO/CPU events, and performance.

## Prerequisites

### 1. PostgreSQL with pg_10046 Extension

The extension must be loaded via `shared_preload_libraries`:

```bash
# In postgresql.conf
shared_preload_libraries = 'pg_10046'
```

Restart PostgreSQL after adding the extension.

### 2. Python Dependencies

```bash
pip install psycopg2-binary
```

### 3. Environment Variables

Set PostgreSQL connection parameters:

```bash
export PGHOST=/var/run/postgresql   # or localhost
export PGPORT=5432                   # default
export PGUSER=postgres
export PGPASSWORD=                   # if needed
export PGDATABASE=postgres

# Optional: trace file directory (default: /tmp)
export PG10046_TRACE_DIR=/tmp
```

## Running Tests

### Run All Tests

```bash
cd /path/to/pg_10046/tests
python3 run_tests.py
```

### Run with Verbose Output

```bash
python3 run_tests.py -v      # verbose
python3 run_tests.py -vv     # more verbose
```

### Run Specific Test Module

```bash
python3 run_tests.py simple       # test_simple_queries.py
python3 run_tests.py node         # test_node_tracking.py
python3 run_tests.py cross        # test_cross_backend.py
python3 run_tests.py sampling     # test_sampling.py
python3 run_tests.py ebpf         # test_ebpf_io.py (requires root)
python3 run_tests.py bind         # test_bind_and_plan.py
python3 run_tests.py perf         # test_performance.py
```

### Run eBPF Tests (Requires Root)

eBPF tests require root privileges and the pg_10046 daemon running:

```bash
# Start the daemon first
sudo python3 /usr/local/bin/pg_10046d.py &

# Run eBPF tests as root
sudo PGHOST=/var/run/postgresql PGUSER=postgres python3 run_tests.py ebpf
```

### Run Tests Matching Keyword

```bash
python3 run_tests.py -k "join"      # all tests with "join" in name
python3 run_tests.py -k "limit"     # all LIMIT-related tests
python3 run_tests.py -k "hash"      # hash join tests
```

### List Available Tests

```bash
python3 run_tests.py --list
```

### Stop on First Failure

```bash
python3 run_tests.py -f
python3 run_tests.py --failfast
```

### Skip Prerequisite Check

```bash
python3 run_tests.py --skip-prereq
```

## Validating Trace Files

Validate a trace file outside of the test suite:

```bash
python3 run_tests.py --validate /tmp/pg_10046_12345_20260113120000.trc
```

This will:
1. Parse the trace file
2. Run all validation checks
3. Report any errors or warnings
4. Run assertion checks

## Test Categories

### test_simple_queries.py (16 tests)

Basic trace correctness for common SQL operations:

| Test | Description |
|------|-------------|
| `test_simple_select` | Single SELECT with WHERE clause |
| `test_select_count` | COUNT(*) aggregation |
| `test_select_with_filter` | SELECT with complex WHERE |
| `test_select_with_order` | SELECT with ORDER BY and LIMIT |
| `test_insert_query` | INSERT with RETURNING |
| `test_update_query` | UPDATE statement |
| `test_delete_query` | DELETE statement |
| `test_multiple_queries` | Multiple queries in one session |
| `test_header_fields` | Trace header validation |
| `test_statistics_present` | Execution statistics capture |
| `test_empty_result` | Query returning no rows |
| `test_large_result` | Query with 1000+ rows |
| `test_explain_is_traced` | EXPLAIN queries are traced |
| `test_set_command` | SET command handling |
| `test_transaction_commands` | Transaction handling |
| `test_*_node` | Plan node capture tests |

### test_node_tracking.py (24 tests)

NODE_START/NODE_END pairing and complex plans:

| Test | Description |
|------|-------------|
| `test_simple_join` | Two-table JOIN |
| `test_three_way_join` | Three-table JOIN |
| `test_hash_join` | Hash Join node tracking |
| `test_nested_loop` | Nested Loop node tracking |
| `test_merge_join` | Merge Join node tracking |
| `test_subquery` | Subquery node tracking |
| `test_cte_query` | WITH clause (CTE) |
| `test_union_query` | UNION query |
| `test_limit_1` | LIMIT 1 cascade |
| `test_limit_10` | LIMIT 10 cascade |
| `test_limit_with_offset` | LIMIT with OFFSET |
| `test_limit_zero_rows` | LIMIT 0 |
| `test_limit_on_join` | LIMIT on CROSS JOIN |
| `test_five_table_join` | 5-table JOIN with aggregation |
| `test_window_function` | Window functions |
| `test_recursive_cte` | Recursive CTE |
| `test_lateral_join` | LATERAL JOIN |
| `test_node_end_after_start` | Timing validation |
| `test_child_within_parent` | Nested node timing |

### test_cross_backend.py (19 tests)

Cross-backend trace enable functionality:

| Test | Description |
|------|-------------|
| `test_enable_trace_basic` | Basic enable_trace() |
| `test_enable_trace_ebpf` | enable_trace_ebpf() variant |
| `test_disable_trace_clears_request` | disable_trace() works |
| `test_enable_on_nonexistent_pid` | Non-existent PID handling |
| `test_enable_on_self` | Self-trace |
| `test_two_concurrent_traces` | Two concurrent sessions |
| `test_five_concurrent_traces` | Five concurrent sessions |
| `test_enable_before_query` | Enable before first query |
| `test_multiple_queries_single_trace` | Multiple queries per trace |
| `test_rapid_queries` | 20 rapid queries |
| `test_concurrent_queries_threads` | Multi-threaded queries |
| `test_traced_session_context` | Harness context manager |
| `test_double_enable` | Double enable handling |
| `test_disable_without_enable` | Disable without enable |
| `test_negative_pid` | Negative PID handling |
| `test_zero_pid` | Zero PID handling |

### test_sampling.py (14 tests)

SAMPLE events, wait events, and CPU tracking:

| Test | Description |
|------|-------------|
| `test_long_query_generates_samples` | SAMPLE events for slow queries |
| `test_sample_interval_header` | SAMPLE_INTERVAL_MS in header |
| `test_sample_has_node_attribution` | Samples have node pointer |
| `test_sample_count_in_sampling_end` | SAMPLING_END reports count |
| `test_wait_event_format` | Wait event hex format |
| `test_io_wait_captured` | IO waits during disk reads |
| `test_samples_have_timestamps` | Valid timestamps |
| `test_sample_timestamps_increase` | Monotonic timestamps |
| `test_samples_within_execution` | Samples within EXEC_START/END |
| `test_cpu_intensive_query_samples` | CPU samples without waits |
| `test_sample_progress_stats` | Tuple/block counts in samples |
| `test_fast_query_no_samples` | Fast queries may skip samples |
| `test_multiple_queries_sampling` | Sampling across queries |
| `test_cancelled_query_sampling` | Proper SAMPLING_START/END pairing |

### test_ebpf_io.py (23 tests) - Requires Root

eBPF daemon IO and CPU event capture:

| Test | Description |
|------|-------------|
| `test_parse_io_read_event` | Parse IO_READ event line |
| `test_parse_io_write_event` | Parse IO_WRITE event line |
| `test_parse_multiple_events` | Parse mixed IO events |
| `test_daemon_socket_exists` | Daemon socket at /var/run/pg_10046.sock |
| `test_read_generates_io_events` | Table reads generate IO_READ |
| `test_io_read_has_timing` | IO events have elapsed_us |
| `test_write_generates_io_events` | INSERTs generate IO_WRITE |
| `test_io_has_node_pointer` | IO events have node_ptr |
| `test_io_relation_matches_query` | IO events reference correct table |
| `test_trace_mentions_io_file` | Main trace references IO trace |
| `test_io_trace_uuid_matches` | IO trace UUID matches main trace |
| `test_io_event_fields_valid` | All IO fields are valid |
| `test_io_timestamps_ordered` | IO timestamps are ordered |
| `test_parse_cpu_off_event` | Parse CPU_OFF event |
| `test_parse_cpu_on_event` | Parse CPU_ON event |
| `test_parse_mixed_events` | Parse IO and CPU events |
| `test_cpu_event_has_node_ptr` | CPU events have node pointer |
| `test_cpu_intensive_generates_events` | CPU work generates events |
| `test_cpu_events_have_timing` | CPU events have duration_us |
| `test_cpu_off_on_pairing` | CPU_OFF/CPU_ON roughly paired |
| `test_cpu_duration_reasonable` | CPU durations are reasonable |
| `test_ebpf_trace_summary` | Summary properties work |

### test_bind_and_plan.py (25 tests)

Bind variables, plan tree output, and node-specific info:

| Test | Description |
|------|-------------|
| `test_simple_parameterized_query` | BIND capture with $1 |
| `test_multiple_bind_variables` | Multiple $1, $2, $3 binds |
| `test_bind_variable_types` | Integer, text type capture |
| `test_null_bind_variable` | NULL parameter capture |
| `test_bind_count_in_binds_start` | BINDS_START parameter count |
| `test_plan_start_end_markers` | PLAN_START/PLAN_END present |
| `test_plan_contains_node_type` | Plan has node types (SeqScan) |
| `test_plan_contains_index_scan` | IndexScan in plan |
| `test_plan_contains_join` | Join nodes in plan |
| `test_plan_has_cost_estimates` | Cost values in PLAN lines |
| `test_plan_has_row_estimates` | Row estimates in PLAN lines |
| `test_plan_time_captured` | PLAN_TIME captured |
| `test_plan_tree_hierarchy` | Valid parent-child relationships |
| `test_prepare_is_traced` | PREPARE/EXECUTE traced |
| `test_execute_is_traced` | EXECUTE with bind values |
| `test_multiple_executes` | Multiple EXECUTE calls |
| `test_prepared_statement_replan` | Replan detection |
| `test_sort_info_captured` | SORT method/space info |
| `test_hash_info_captured` | HASH buckets/batches info |
| `test_index_info_captured` | INDEX name capture |
| `test_sort_method_types` | Different sort methods |
| `test_stats_section_complete` | STATS_START/END complete |
| `test_plan_matches_explain` | Plan matches EXPLAIN |
| `test_root_node_has_no_parent` | Root has parent_id=0 |
| `test_all_nodes_have_valid_ids` | All nodes have positive IDs |

### test_performance.py (25 tests)

Performance measurement and benchmarks:

| Test | Description |
|------|-------------|
| `test_simple_select_overhead` | Simple SELECT overhead % |
| `test_aggregation_overhead` | Aggregation query overhead |
| `test_join_overhead` | JOIN query overhead |
| `test_sort_overhead` | ORDER BY query overhead |
| `test_rapid_queries_throughput` | QPS for rapid queries |
| `test_mixed_query_throughput` | QPS for mixed queries |
| `test_sustained_throughput` | Sustained QPS over 5 seconds |
| `test_1k_rows_result` | Trace size for 1K rows |
| `test_10k_rows_result` | Trace size for 10K rows |
| `test_full_table_scan` | Trace for 100K row scan |
| `test_large_sort` | Large sort operation |
| `test_two_concurrent_sessions` | 2 concurrent traced sessions |
| `test_five_concurrent_sessions` | 5 concurrent traced sessions |
| `test_concurrent_with_untraced` | Impact on untraced sessions |
| `test_simple_query_trace_size` | Simple query trace bytes |
| `test_complex_query_trace_size` | Complex query trace bytes |
| `test_many_queries_trace_size` | Linear scaling verification |
| `test_trace_size_with_bind_variables` | Bind variable trace size |
| `test_sleep_query` | pg_sleep tracing |
| `test_cpu_intensive_query` | CPU-intensive query |
| `test_io_intensive_query` | IO-intensive query |
| `test_ebpf_high_io_rate` | eBPF with high IO (root) |
| `test_ebpf_cpu_intensive` | eBPF CPU workload (root) |
| `test_repeated_trace_sessions` | Memory stability |
| `test_large_trace_cleanup` | Large trace handling |

## Understanding Performance Test Results

Performance tests print detailed metrics. Here's how to interpret them:

### Overhead Metrics

```
Simple SELECT overhead (50 queries):
  Baseline: 0.68ms/query (34ms total)
  Traced:   3.00ms/query (150ms total)
  Overhead: 341%
```

- **Baseline**: Average query time without tracing
- **Traced**: Average query time with tracing enabled
- **Overhead**: Percentage increase due to tracing

**Expected values**: 100-500% overhead is normal due to trace file I/O and fsync.

### Throughput Metrics

```
Sustained throughput (5s):
  Queries: 1994
  QPS: 398.6
```

- **QPS**: Queries per second achieved
- **Expected**: 200-500 QPS for simple queries on typical hardware

### Trace Size Metrics

```
Trace size scaling:
  10 queries: 7,134 bytes (713 bytes/query)
  50 queries: 34,094 bytes (682 bytes/query)
  100 queries: 67,849 bytes (678 bytes/query)
```

- **Bytes/query**: Should remain roughly constant (linear scaling)
- **Expected**: 500-1000 bytes per simple query

### Concurrent Session Metrics

```
5 concurrent sessions:
  Total queries: 150
  Total time: 0.39s
  QPS: 381.3
```

- Shows aggregate throughput with multiple traced sessions
- QPS should not drop significantly with more sessions

### Typical Results Summary

| Metric | Expected Range | Notes |
|--------|---------------|-------|
| Simple query overhead | 100-500% | Higher on slow disk |
| Throughput (QPS) | 200-500 | Depends on hardware |
| Trace size per query | 500-1000 bytes | Linear scaling |
| Concurrent session QPS | 300-400 | Slight decrease OK |
| Trace for 10K rows | 5-10 KB | Not proportional to rows |

## Using the Test Library

### Parsing Trace Files

```python
from lib.trace_validator import TraceParser

parser = TraceParser("/tmp/pg_10046_12345_*.trc")
trace = parser.parse()

print(f"Queries: {len(trace.queries)}")
print(f"Events: {len(trace.events)}")
print(f"Nodes: {len(trace.node_starts)}")

for query in trace.queries:
    print(f"  SQL: {query.sql[:50]}...")
    print(f"  Elapsed: {query.elapsed_us} us")
```

### Validating Trace Files

```python
from lib.trace_validator import TraceValidator

validator = TraceValidator("/tmp/pg_10046_12345_*.trc")
result = validator.validate()

print(f"Valid: {result.is_valid}")
print(f"Errors: {len(result.errors)}")
print(f"Warnings: {len(result.warnings)}")

for error in result.errors:
    print(f"  [{error.error_type}] Line {error.line_num}: {error.message}")
```

### Using Assertions

```python
from lib.assertions import *

# Parse and validate
trace = parse_trace("/tmp/pg_10046_12345_*.trc")

# Check header
assert_header_present(trace, ['TRACE_ID', 'PID', 'START_TIME'])

# Check queries
assert_query_count(trace, 3)
assert_query_captured(trace, r"SELECT.*FROM users")

# Check nodes
assert_all_nodes_paired(trace)
assert_node_timing_valid(trace)

# Check stats
assert_stats_present(trace)

# All-in-one validation
trace = assert_basic_trace_correctness("/tmp/pg_10046_12345_*.trc")
```

### Using the Test Harness

```python
from lib.pg_harness import PgHarness

harness = PgHarness()

# Simple traced session
with harness.traced_session() as session:
    result = session.execute("SELECT * FROM users WHERE id = 1")
    print(f"Rows: {len(result.rows)}")

    trace = session.get_trace()
    print(f"Trace: {trace.path}")

# Multiple concurrent sessions
with harness.multiple_sessions(3) as sessions:
    for i, s in enumerate(sessions):
        s.execute(f"SELECT {i}")

    for s in sessions:
        trace = s.get_trace()
        print(f"Session {s.conn.pid}: {trace.path}")

# With eBPF flag
with harness.traced_session(ebpf_active=True) as session:
    session.execute("SELECT 1")

# Cleanup
harness.cleanup()
```

### Comparing Trace to EXPLAIN

```python
from lib.pg_harness import PgHarness, compare_trace_to_explain

harness = PgHarness()

with harness.traced_session() as session:
    # Execute query (also runs EXPLAIN ANALYZE)
    result = session.execute("SELECT * FROM users ORDER BY id LIMIT 10")

    # Get trace and explain
    trace = session.get_trace()
    explains = session.get_explains()

    # Compare
    comparison = compare_trace_to_explain(trace.path, explains[0])

    print(f"Nodes match: {comparison['nodes_match']}")
    print(f"Row counts match: {comparison['row_counts_match']}")
    print(f"Timing reasonable: {comparison['timing_reasonable']}")

    for diff in comparison['differences']:
        print(f"  - {diff}")
```

## Writing New Tests

### Basic Test Structure

```python
import unittest
from lib.pg_harness import PgHarness
from lib.assertions import *

class TestMyFeature(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()
        # Create test tables if needed
        conn = cls.harness.new_connection()
        conn.execute("CREATE TABLE IF NOT EXISTS my_test (...)")
        conn.close()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def test_my_feature(self):
        with self.harness.traced_session() as session:
            result = session.execute("SELECT * FROM my_test", with_explain=False)

            trace_info = session.get_trace()
            self.assertIsNotNone(trace_info)

            trace = parse_trace(trace_info.path)

            # Assertions
            assert_query_count(trace, 1)
            assert_all_nodes_paired(trace)

if __name__ == '__main__':
    unittest.main()
```

### Key Guidelines

1. **Use `with_explain=False`** when counting exact query numbers
2. **Don't drop tables in tearDownClass** - other tests may need them
3. **Add `setUp()` method** to ensure test tables exist
4. **Use `assert_basic_trace_correctness()`** for standard validation
5. **Check `result.error`** before asserting on results

## Troubleshooting

### "psycopg2 not installed"

```bash
pip install psycopg2-binary
```

### "pg_10046 extension not loaded"

Add to `postgresql.conf`:
```
shared_preload_libraries = 'pg_10046'
```
Then restart PostgreSQL.

### "Peer authentication failed"

Run tests as the postgres user:
```bash
sudo -u postgres python3 run_tests.py
```

Or set `PGHOST` to use socket authentication:
```bash
export PGHOST=/var/run/postgresql
```

### "No trace file found"

1. Check trace directory permissions
2. Verify extension is loaded: `SELECT * FROM pg_extension WHERE extname = 'pg_10046'`
3. Check trace_10046 schema exists: `\dn trace_10046`

### Tests failing with "0 queries"

The trace file may be empty or cleaned up. Run tests with `--skip-prereq` to skip the prerequisite check, or check that the PostgreSQL connection is working.

## Architecture

```
tests/
├── run_tests.py              # Main entry point
├── README.md                 # This file
├── lib/
│   ├── __init__.py
│   ├── trace_validator.py    # Trace parsing and validation
│   ├── pg_harness.py         # PostgreSQL test harness
│   └── assertions.py         # Reusable assertion functions
├── test_simple_queries.py    # Basic query tests (16 tests)
├── test_node_tracking.py     # Node pairing tests (24 tests)
├── test_cross_backend.py     # Cross-backend tests (19 tests)
├── test_sampling.py          # SAMPLE/wait events (14 tests)
├── test_ebpf_io.py           # eBPF IO/CPU events (23 tests)
├── test_bind_and_plan.py     # Bind vars, plan tree (25 tests)
└── test_performance.py       # Performance benchmarks (25 tests)
```

### trace_validator.py

- `TraceParser` - Parses trace files into structured data
- `TraceValidator` - Runs validation checks
- `TraceFile` - Container for parsed trace data
- `TraceEvent` - Single trace event
- `QueryExecution` - Query with plan and stats
- `IOEvent` - IO_READ/IO_WRITE event from eBPF
- `CPUEvent` - CPU_OFF/CPU_ON event from eBPF
- `EBPFTraceFile` - Container for eBPF trace data
- `IOTraceParser` - Parses eBPF IO/CPU trace files

### pg_harness.py

- `PgHarness` - Main test harness
- `PgConnection` - PostgreSQL connection wrapper
- `TracedSession` - Session with tracing enabled
- `compare_trace_to_explain()` - Compare trace to EXPLAIN output

### assertions.py

- Header assertions: `assert_header_present()`, `assert_header_value()`
- Query assertions: `assert_query_count()`, `assert_query_captured()`
- Node assertions: `assert_all_nodes_paired()`, `assert_node_timing_valid()`
- Stats assertions: `assert_stats_present()`, `assert_tuple_count()`
- Composite: `assert_basic_trace_correctness()`, `assert_trace_complete_and_valid()`
