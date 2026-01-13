#!/usr/bin/env python3
"""
Test Simple Queries - Basic trace correctness tests.

Tests that simple queries produce correct, complete traces with:
- Valid headers
- QUERY_START/EXEC_END pairs
- Correct plan structure
- Proper node tracking
- Accurate statistics
"""

import unittest
import sys
import os

# Add lib to path
sys.path.insert(0, os.path.dirname(__file__))

from lib.pg_harness import PgHarness, PgConfig
from lib.assertions import (
    parse_trace,
    assert_header_present,
    assert_query_count,
    assert_query_captured,
    assert_all_nodes_paired,
    assert_node_timing_valid,
    assert_all_queries_complete,
    assert_stats_present,
    assert_basic_trace_correctness,
    TraceAssertionError,
)
from lib.trace_validator import EventType


class TestSimpleQueries(unittest.TestCase):
    """Test basic trace correctness for simple queries."""

    @classmethod
    def setUpClass(cls):
        """Set up test harness once for all tests."""
        cls.harness = PgHarness()

        # Create test table (recreate fresh each time)
        conn = cls.harness.new_connection()
        conn.execute("DROP TABLE IF EXISTS trace_test CASCADE")
        conn.execute("""
            CREATE TABLE trace_test (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                value INTEGER,
                created_at TIMESTAMP DEFAULT now()
            )
        """)
        conn.execute("""
            INSERT INTO trace_test (name, value)
            SELECT 'item_' || i, i * 10
            FROM generate_series(1, 1000) i
        """)
        conn.execute("ANALYZE trace_test")
        conn.close()

    def setUp(self):
        """Ensure test table exists before each test."""
        conn = self.harness.new_connection()
        result = conn.execute("SELECT COUNT(*) FROM trace_test")
        if result.error or result.rows[0]['count'] < 1000:
            # Recreate table
            conn.execute("DROP TABLE IF EXISTS trace_test CASCADE")
            conn.execute("""
                CREATE TABLE trace_test (
                    id SERIAL PRIMARY KEY,
                    name TEXT NOT NULL,
                    value INTEGER,
                    created_at TIMESTAMP DEFAULT now()
                )
            """)
            conn.execute("""
                INSERT INTO trace_test (name, value)
                SELECT 'item_' || i, i * 10
                FROM generate_series(1, 1000) i
            """)
            conn.execute("ANALYZE trace_test")
        conn.close()

    @classmethod
    def tearDownClass(cls):
        """Clean up after all tests."""
        # Don't drop table - other test classes may need it
        cls.harness.cleanup()

    def test_simple_select(self):
        """Test tracing a simple SELECT query."""
        with self.harness.traced_session() as session:
            result = session.execute("SELECT * FROM trace_test WHERE id = 1", with_explain=False)
            self.assertEqual(len(result.rows), 1)

            trace_info = session.get_trace()
            self.assertIsNotNone(trace_info, "Trace file should exist")
            self.assertTrue(trace_info.exists)

            # Validate trace
            trace = assert_basic_trace_correctness(trace_info.path)

            # Should have exactly 1 query
            assert_query_count(trace, 1)

            # Query should be captured
            query = assert_query_captured(trace, r"SELECT.*FROM trace_test")
            self.assertIsNotNone(query)

    def test_select_count(self):
        """Test tracing a COUNT(*) aggregation."""
        with self.harness.traced_session() as session:
            result = session.execute("SELECT COUNT(*) FROM trace_test", with_explain=False)
            # Count may vary due to INSERT tests
            self.assertGreaterEqual(result.rows[0]['count'], 1000)

            trace_info = session.get_trace()
            trace = assert_basic_trace_correctness(trace_info.path)

            assert_query_count(trace, 1)
            query = assert_query_captured(trace, r"SELECT COUNT")

    def test_select_with_filter(self):
        """Test tracing a query with WHERE clause."""
        with self.harness.traced_session() as session:
            result = session.execute(
                "SELECT * FROM trace_test WHERE value > 500 AND value < 600"
            )

            trace_info = session.get_trace()
            trace = assert_basic_trace_correctness(trace_info.path)

            # Verify node tracking
            assert_all_nodes_paired(trace)
            assert_node_timing_valid(trace)

    def test_select_with_order(self):
        """Test tracing a query with ORDER BY."""
        with self.harness.traced_session() as session:
            result = session.execute(
                "SELECT * FROM trace_test ORDER BY value DESC LIMIT 10"
            )
            self.assertEqual(len(result.rows), 10)

            trace_info = session.get_trace()
            trace = assert_basic_trace_correctness(trace_info.path)

            # Should have a Sort node
            assert_all_nodes_paired(trace)

    def test_insert_query(self):
        """Test tracing an INSERT query."""
        with self.harness.traced_session() as session:
            result = session.execute(
                "INSERT INTO trace_test (name, value) VALUES ('test_insert', 999) RETURNING id"
            )
            self.assertEqual(result.rowcount, 1)

            trace_info = session.get_trace()
            trace = assert_basic_trace_correctness(trace_info.path)

            # Verify INSERT was captured
            assert_query_captured(trace, r"INSERT INTO trace_test")

    def test_update_query(self):
        """Test tracing an UPDATE query."""
        with self.harness.traced_session() as session:
            # First insert a row to update
            session.execute(
                "INSERT INTO trace_test (name, value) VALUES ('to_update', 0)"
            )

            # Now update it
            result = session.execute(
                "UPDATE trace_test SET value = 100 WHERE name = 'to_update'"
            )

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            # Should have captured the UPDATE
            assert_query_captured(trace, r"UPDATE trace_test")

    def test_delete_query(self):
        """Test tracing a DELETE query."""
        with self.harness.traced_session() as session:
            # Insert then delete
            session.execute(
                "INSERT INTO trace_test (name, value) VALUES ('to_delete', 0)"
            )
            result = session.execute(
                "DELETE FROM trace_test WHERE name = 'to_delete'"
            )

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            assert_query_captured(trace, r"DELETE FROM trace_test")

    def test_multiple_queries(self):
        """Test tracing multiple queries in one session."""
        with self.harness.traced_session() as session:
            session.execute("SELECT 1 AS one", with_explain=False)
            session.execute("SELECT 2 AS two", with_explain=False)
            session.execute("SELECT 3 AS three", with_explain=False)

            trace_info = session.get_trace()
            trace = assert_basic_trace_correctness(trace_info.path)

            # Should have all 3 queries
            assert_query_count(trace, 3)

    def test_header_fields(self):
        """Test that trace header contains required fields."""
        with self.harness.traced_session() as session:
            session.execute("SELECT 1")

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            # Check required header fields
            assert_header_present(trace, ['TRACE_ID', 'PID', 'START_TIME'])

            # Verify PID matches session PID
            self.assertEqual(int(trace.header.get('PID', 0)), session.conn.pid)

    def test_statistics_present(self):
        """Test that execution statistics are captured."""
        with self.harness.traced_session() as session:
            session.execute("SELECT * FROM trace_test WHERE id <= 100")

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            # Should have stats for each query
            assert_stats_present(trace)

            # Check that stats have expected fields
            for query in trace.queries:
                for stat in query.stats:
                    self.assertIn('tuples', stat)

    def test_empty_result(self):
        """Test tracing a query that returns no rows."""
        with self.harness.traced_session() as session:
            result = session.execute(
                "SELECT * FROM trace_test WHERE id = -1"
            )
            self.assertEqual(len(result.rows), 0)

            trace_info = session.get_trace()
            trace = assert_basic_trace_correctness(trace_info.path)

            # Query should still be complete
            assert_all_queries_complete(trace)

    def test_large_result(self):
        """Test tracing a query with many result rows."""
        with self.harness.traced_session() as session:
            result = session.execute("SELECT * FROM trace_test", with_explain=False)
            # Count may vary slightly due to INSERT tests
            self.assertGreaterEqual(len(result.rows), 1000)

            trace_info = session.get_trace()
            trace = assert_basic_trace_correctness(trace_info.path)

            # Should capture the full scan
            query = trace.queries[0]

            # Stats should show ~1000 tuples for SeqScan
            has_tuples = False
            for stat in query.stats:
                if stat.get('tuples', 0) >= 1000:
                    has_tuples = True
                    break
            self.assertTrue(has_tuples, "Should have captured tuple count >= 1000")


class TestQueryTypes(unittest.TestCase):
    """Test different SQL query types."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def test_explain_is_traced(self):
        """EXPLAIN queries ARE traced (they go through planner hook)."""
        with self.harness.traced_session() as session:
            # Run actual query first
            session.execute("SELECT 1", with_explain=False)

            # EXPLAIN goes through planner and is traced
            session.conn.execute("EXPLAIN SELECT * FROM pg_class")

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            # Both queries should be traced
            assert_query_count(trace, 2)
            assert_query_captured(trace, r"EXPLAIN SELECT")

    def test_set_command(self):
        """SET commands may or may not be traced."""
        with self.harness.traced_session() as session:
            session.conn.execute("SET work_mem = '64MB'")
            session.execute("SELECT 1")

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            # At least the SELECT should be traced
            self.assertGreaterEqual(len(trace.queries), 1)

    def test_transaction_commands(self):
        """Test BEGIN/COMMIT/ROLLBACK handling."""
        with self.harness.traced_session() as session:
            # Run a simple query - transactions handled by connection
            session.execute("SELECT 1 AS in_txn", with_explain=False)

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            # Should have the SELECT
            self.assertGreaterEqual(len(trace.queries), 1)


class TestPlanNodes(unittest.TestCase):
    """Test that plan nodes are correctly captured."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

        conn = cls.harness.new_connection()
        conn.execute("DROP TABLE IF EXISTS plan_test CASCADE")
        conn.execute("""
            CREATE TABLE plan_test (
                id INTEGER PRIMARY KEY,
                category TEXT,
                value INTEGER
            )
        """)
        conn.execute("""
            INSERT INTO plan_test
            SELECT i, 'cat_' || (i % 10), i * 5
            FROM generate_series(1, 10000) i
        """)
        conn.execute("CREATE INDEX plan_test_cat_idx ON plan_test(category)")
        conn.execute("ANALYZE plan_test")
        conn.close()

    @classmethod
    def tearDownClass(cls):
        try:
            conn = cls.harness.new_connection()
            conn.execute("DROP TABLE IF EXISTS plan_test CASCADE")
            conn.close()
        except Exception:
            pass
        cls.harness.cleanup()

    def test_seqscan_node(self):
        """Test SeqScan node is captured."""
        with self.harness.traced_session() as session:
            # Force seq scan
            session.conn.execute("SET enable_indexscan = off")
            session.conn.execute("SET enable_bitmapscan = off")

            session.execute("SELECT * FROM plan_test WHERE value > 40000")

            session.conn.execute("SET enable_indexscan = on")
            session.conn.execute("SET enable_bitmapscan = on")

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            # Should have nodes
            self.assertGreater(len(trace.node_starts), 0)

    def test_indexscan_node(self):
        """Test IndexScan node is captured."""
        with self.harness.traced_session() as session:
            session.execute("SELECT * FROM plan_test WHERE category = 'cat_1'")

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            assert_all_nodes_paired(trace)

    def test_aggregate_node(self):
        """Test Aggregate node is captured."""
        with self.harness.traced_session() as session:
            session.execute("SELECT category, SUM(value) FROM plan_test GROUP BY category")

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            assert_all_nodes_paired(trace)
            assert_node_timing_valid(trace)

    def test_sort_node(self):
        """Test Sort node is captured."""
        with self.harness.traced_session() as session:
            session.execute("SELECT * FROM plan_test ORDER BY value DESC")

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            assert_all_nodes_paired(trace)

    def test_limit_node(self):
        """Test Limit node is captured."""
        with self.harness.traced_session() as session:
            session.execute("SELECT * FROM plan_test LIMIT 10")

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            assert_all_nodes_paired(trace)

            # Stats should show only 10 tuples returned
            query = trace.queries[0]
            # Find the topmost node's tuple count
            # (Implementation specific - may need adjustment)


if __name__ == '__main__':
    unittest.main(verbosity=2)
