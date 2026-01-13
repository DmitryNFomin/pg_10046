# pg_10046 Test Framework

Comprehensive test suite for validating pg_10046 trace correctness.

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

### test_cross_backend.py (18 tests)

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
├── lib/
│   ├── __init__.py
│   ├── trace_validator.py    # Trace parsing and validation
│   ├── pg_harness.py         # PostgreSQL test harness
│   └── assertions.py         # Reusable assertion functions
├── test_simple_queries.py    # Basic query tests
├── test_node_tracking.py     # Node pairing tests
└── test_cross_backend.py     # Cross-backend tests
```

### trace_validator.py

- `TraceParser` - Parses trace files into structured data
- `TraceValidator` - Runs validation checks
- `TraceFile` - Container for parsed trace data
- `TraceEvent` - Single trace event
- `QueryExecution` - Query with plan and stats

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
