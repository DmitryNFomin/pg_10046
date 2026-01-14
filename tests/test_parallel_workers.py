#!/usr/bin/env python3
"""
Test Parallel Worker Tracing - Tests for parallel query worker auto-tracing.

Tests that:
- Parallel workers automatically inherit tracing from leader
- Worker trace files have correct correlation headers
- All workers produce separate trace files
- Worker IDs are unique and correct
- Total tuples from leader + workers equals expected
- Node tracking works correctly in parallel workers
"""

import unittest
import sys
import os
import glob
import time

sys.path.insert(0, os.path.dirname(__file__))

from lib.pg_harness import PgHarness, PgConfig, TraceInfo
from lib.assertions import (
    parse_trace,
    assert_header_present,
    assert_all_nodes_paired,
    assert_node_timing_valid,
    assert_is_parallel_worker_trace,
    assert_is_leader_trace,
    assert_worker_trace_correlates_to_leader,
    assert_worker_ids_unique,
    assert_parallel_tuples_complete,
    TraceAssertionError,
)


class ParallelTestHarness(PgHarness):
    """Extended harness with parallel query support."""

    def enable_parallel_query(self, conn, workers: int = 4):
        """Configure session for parallel query execution."""
        conn.execute(f"SET max_parallel_workers_per_gather = {workers}")
        conn.execute("SET parallel_tuple_cost = 0")
        conn.execute("SET parallel_setup_cost = 0")
        conn.execute("SET min_parallel_table_scan_size = 0")
        conn.execute("SET min_parallel_index_scan_size = 0")

    def get_all_trace_files(self, timeout_sec: float = 5.0):
        """Get all trace files created during the session.

        Returns:
            Tuple of (leader_trace_path, list_of_worker_trace_paths)
        """
        pattern = f"{self.config.trace_dir}/pg_10046_*.trc"
        start = time.time()

        while time.time() - start < timeout_sec:
            files = glob.glob(pattern)
            if files:
                # Sort by modification time
                files.sort(key=os.path.getmtime)
                # First file is usually leader, rest are workers
                # But we should check headers to be sure
                return files
            time.sleep(0.1)

        return []

    def separate_leader_and_workers(self, trace_paths):
        """Separate trace files into leader and workers based on headers.

        Returns:
            Tuple of (leader_trace, list_of_worker_traces)
        """
        leader = None
        workers = []

        for path in trace_paths:
            trace = parse_trace(path)
            if 'LEADER_PID' in trace.header:
                workers.append(trace)
            else:
                leader = trace

        return leader, workers


class TestParallelWorkerTraceCreation(unittest.TestCase):
    """Test that parallel workers create trace files."""

    @classmethod
    def setUpClass(cls):
        cls.harness = ParallelTestHarness()

        # Create a large table for parallel queries
        conn = cls.harness.new_connection()
        conn.execute("DROP TABLE IF EXISTS parallel_trace_test CASCADE")
        conn.execute("""
            CREATE TABLE parallel_trace_test (
                id SERIAL PRIMARY KEY,
                data TEXT,
                value INTEGER
            )
        """)
        conn.execute("""
            INSERT INTO parallel_trace_test (data, value)
            SELECT md5(i::text), i % 1000
            FROM generate_series(1, 100000) i
        """)
        conn.execute("ANALYZE parallel_trace_test")
        conn.close()

    @classmethod
    def tearDownClass(cls):
        try:
            conn = cls.harness.new_connection()
            conn.execute("DROP TABLE IF EXISTS parallel_trace_test CASCADE")
            conn.close()
        except Exception:
            pass
        cls.harness.cleanup()

    def test_parallel_workers_create_traces(self):
        """Test that parallel workers create separate trace files."""
        self.harness.cleanup_traces()

        conn = self.harness.new_connection()
        control = self.harness.new_connection()

        try:
            # Enable tracing
            control.execute(f"SELECT trace_10046.enable_trace({conn.pid})")

            # Enable parallel execution
            self.harness.enable_parallel_query(conn, workers=2)

            # Run parallel query
            result = conn.execute("SELECT count(*) FROM parallel_trace_test")
            self.assertEqual(result.rows[0]['count'], 100000)

            # Close connection to flush traces
            conn.close()
            time.sleep(0.5)

            # Check trace files
            trace_files = self.harness.get_all_trace_files()
            self.assertGreaterEqual(len(trace_files), 2,
                "Should have at least leader + 1 worker trace")

        finally:
            control.close()

    def test_worker_trace_has_correct_headers(self):
        """Test that worker traces have LEADER_PID, LEADER_TRACE_UUID, WORKER_ID."""
        self.harness.cleanup_traces()

        conn = self.harness.new_connection()
        control = self.harness.new_connection()

        try:
            control.execute(f"SELECT trace_10046.enable_trace({conn.pid})")
            self.harness.enable_parallel_query(conn, workers=2)

            conn.execute("SELECT count(*) FROM parallel_trace_test")
            conn.close()
            time.sleep(0.5)

            trace_files = self.harness.get_all_trace_files()
            leader, workers = self.harness.separate_leader_and_workers(trace_files)

            self.assertIsNotNone(leader, "Should have leader trace")
            self.assertGreater(len(workers), 0, "Should have at least one worker trace")

            # Check worker headers
            for worker in workers:
                assert_is_parallel_worker_trace(worker)
                self.assertIn('LEADER_PID', worker.header)
                self.assertIn('LEADER_TRACE_UUID', worker.header)
                self.assertIn('WORKER_ID', worker.header)

        finally:
            control.close()

    def test_leader_trace_has_no_worker_headers(self):
        """Test that leader trace does not have worker-specific headers."""
        self.harness.cleanup_traces()

        conn = self.harness.new_connection()
        control = self.harness.new_connection()

        try:
            control.execute(f"SELECT trace_10046.enable_trace({conn.pid})")
            self.harness.enable_parallel_query(conn, workers=2)

            conn.execute("SELECT count(*) FROM parallel_trace_test")
            conn.close()
            time.sleep(0.5)

            trace_files = self.harness.get_all_trace_files()
            leader, _ = self.harness.separate_leader_and_workers(trace_files)

            self.assertIsNotNone(leader)
            assert_is_leader_trace(leader)

        finally:
            control.close()


class TestParallelWorkerCorrelation(unittest.TestCase):
    """Test correlation between leader and worker traces."""

    @classmethod
    def setUpClass(cls):
        cls.harness = ParallelTestHarness()

        conn = cls.harness.new_connection()
        conn.execute("DROP TABLE IF EXISTS parallel_corr_test CASCADE")
        conn.execute("""
            CREATE TABLE parallel_corr_test (
                id SERIAL PRIMARY KEY,
                data TEXT
            )
        """)
        conn.execute("""
            INSERT INTO parallel_corr_test (data)
            SELECT md5(i::text)
            FROM generate_series(1, 50000) i
        """)
        conn.execute("ANALYZE parallel_corr_test")
        conn.close()

    @classmethod
    def tearDownClass(cls):
        try:
            conn = cls.harness.new_connection()
            conn.execute("DROP TABLE IF EXISTS parallel_corr_test CASCADE")
            conn.close()
        except Exception:
            pass
        cls.harness.cleanup()

    def test_worker_leader_pid_matches(self):
        """Test that LEADER_PID in worker matches leader's PID."""
        self.harness.cleanup_traces()

        conn = self.harness.new_connection()
        control = self.harness.new_connection()
        leader_pid = conn.pid

        try:
            control.execute(f"SELECT trace_10046.enable_trace({conn.pid})")
            self.harness.enable_parallel_query(conn, workers=2)

            conn.execute("SELECT count(*) FROM parallel_corr_test")
            conn.close()
            time.sleep(0.5)

            trace_files = self.harness.get_all_trace_files()
            leader, workers = self.harness.separate_leader_and_workers(trace_files)

            self.assertIsNotNone(leader)
            self.assertEqual(leader.header.get('PID'), str(leader_pid))

            for worker in workers:
                self.assertEqual(worker.header.get('LEADER_PID'), str(leader_pid),
                    f"Worker LEADER_PID should match leader's PID")

        finally:
            control.close()

    def test_worker_leader_uuid_matches(self):
        """Test that LEADER_TRACE_UUID in worker matches leader's TRACE_UUID."""
        self.harness.cleanup_traces()

        conn = self.harness.new_connection()
        control = self.harness.new_connection()

        try:
            control.execute(f"SELECT trace_10046.enable_trace({conn.pid})")
            self.harness.enable_parallel_query(conn, workers=2)

            conn.execute("SELECT count(*) FROM parallel_corr_test")
            conn.close()
            time.sleep(0.5)

            trace_files = self.harness.get_all_trace_files()
            leader, workers = self.harness.separate_leader_and_workers(trace_files)

            self.assertIsNotNone(leader)
            leader_uuid = leader.header.get('TRACE_UUID')

            for worker in workers:
                self.assertEqual(worker.header.get('LEADER_TRACE_UUID'), leader_uuid,
                    f"Worker LEADER_TRACE_UUID should match leader's TRACE_UUID")

        finally:
            control.close()

    def test_correlation_assertion_helper(self):
        """Test the assert_worker_trace_correlates_to_leader helper."""
        self.harness.cleanup_traces()

        conn = self.harness.new_connection()
        control = self.harness.new_connection()

        try:
            control.execute(f"SELECT trace_10046.enable_trace({conn.pid})")
            self.harness.enable_parallel_query(conn, workers=2)

            conn.execute("SELECT count(*) FROM parallel_corr_test")
            conn.close()
            time.sleep(0.5)

            trace_files = self.harness.get_all_trace_files()
            leader, workers = self.harness.separate_leader_and_workers(trace_files)

            self.assertIsNotNone(leader)
            for worker in workers:
                # This should not raise
                assert_worker_trace_correlates_to_leader(worker, leader)

        finally:
            control.close()


class TestParallelWorkerIds(unittest.TestCase):
    """Test parallel worker ID assignment."""

    @classmethod
    def setUpClass(cls):
        cls.harness = ParallelTestHarness()

        conn = cls.harness.new_connection()
        conn.execute("DROP TABLE IF EXISTS parallel_id_test CASCADE")
        conn.execute("""
            CREATE TABLE parallel_id_test (
                id SERIAL PRIMARY KEY,
                data TEXT
            )
        """)
        conn.execute("""
            INSERT INTO parallel_id_test (data)
            SELECT md5(i::text)
            FROM generate_series(1, 100000) i
        """)
        conn.execute("ANALYZE parallel_id_test")
        conn.close()

    @classmethod
    def tearDownClass(cls):
        try:
            conn = cls.harness.new_connection()
            conn.execute("DROP TABLE IF EXISTS parallel_id_test CASCADE")
            conn.close()
        except Exception:
            pass
        cls.harness.cleanup()

    def test_worker_ids_are_unique(self):
        """Test that each worker has a unique WORKER_ID."""
        self.harness.cleanup_traces()

        conn = self.harness.new_connection()
        control = self.harness.new_connection()

        try:
            control.execute(f"SELECT trace_10046.enable_trace({conn.pid})")
            self.harness.enable_parallel_query(conn, workers=4)

            conn.execute("SELECT count(*) FROM parallel_id_test")
            conn.close()
            time.sleep(0.5)

            trace_files = self.harness.get_all_trace_files()
            _, workers = self.harness.separate_leader_and_workers(trace_files)

            if len(workers) > 1:
                assert_worker_ids_unique(workers)

        finally:
            control.close()

    def test_worker_ids_are_sequential(self):
        """Test that worker IDs are sequential starting from 0."""
        self.harness.cleanup_traces()

        conn = self.harness.new_connection()
        control = self.harness.new_connection()

        try:
            control.execute(f"SELECT trace_10046.enable_trace({conn.pid})")
            self.harness.enable_parallel_query(conn, workers=4)

            conn.execute("SELECT count(*) FROM parallel_id_test")
            conn.close()
            time.sleep(0.5)

            trace_files = self.harness.get_all_trace_files()
            _, workers = self.harness.separate_leader_and_workers(trace_files)

            if workers:
                worker_ids = sorted([int(w.header.get('WORKER_ID', -1)) for w in workers])
                # Worker IDs should be 0, 1, 2, ... based on ParallelWorkerNumber
                expected = list(range(len(workers)))
                self.assertEqual(worker_ids, expected,
                    f"Worker IDs should be sequential: expected {expected}, got {worker_ids}")

        finally:
            control.close()


class TestParallelTupleCapture(unittest.TestCase):
    """Test that all tuples are captured across leader and workers."""

    @classmethod
    def setUpClass(cls):
        cls.harness = ParallelTestHarness()
        cls.row_count = 200000

        conn = cls.harness.new_connection()
        conn.execute("DROP TABLE IF EXISTS parallel_tuple_test CASCADE")
        conn.execute("""
            CREATE TABLE parallel_tuple_test (
                id SERIAL PRIMARY KEY,
                data TEXT,
                value INTEGER
            )
        """)
        conn.execute(f"""
            INSERT INTO parallel_tuple_test (data, value)
            SELECT md5(i::text), i % 1000
            FROM generate_series(1, {cls.row_count}) i
        """)
        conn.execute("ANALYZE parallel_tuple_test")
        conn.close()

    @classmethod
    def tearDownClass(cls):
        try:
            conn = cls.harness.new_connection()
            conn.execute("DROP TABLE IF EXISTS parallel_tuple_test CASCADE")
            conn.close()
        except Exception:
            pass
        cls.harness.cleanup()

    def test_all_tuples_captured(self):
        """Test that total tuples from all traces equals table size."""
        self.harness.cleanup_traces()

        conn = self.harness.new_connection()
        control = self.harness.new_connection()

        try:
            control.execute(f"SELECT trace_10046.enable_trace({conn.pid})")
            self.harness.enable_parallel_query(conn, workers=4)

            result = conn.execute("SELECT count(*) FROM parallel_tuple_test")
            self.assertEqual(result.rows[0]['count'], self.row_count)

            conn.close()
            time.sleep(0.5)

            trace_files = self.harness.get_all_trace_files()
            leader, workers = self.harness.separate_leader_and_workers(trace_files)

            self.assertIsNotNone(leader)
            self.assertGreater(len(workers), 0, "Should have parallel workers")

            # Check total tuples
            assert_parallel_tuples_complete(leader, workers, self.row_count)

        finally:
            control.close()

    def test_tuples_distributed_across_workers(self):
        """Test that tuples are distributed across workers (not all in leader)."""
        self.harness.cleanup_traces()

        conn = self.harness.new_connection()
        control = self.harness.new_connection()

        try:
            control.execute(f"SELECT trace_10046.enable_trace({conn.pid})")
            self.harness.enable_parallel_query(conn, workers=4)

            conn.execute("SELECT count(*) FROM parallel_tuple_test")
            conn.close()
            time.sleep(0.5)

            trace_files = self.harness.get_all_trace_files()
            leader, workers = self.harness.separate_leader_and_workers(trace_files)

            # Count tuples in leader's SeqScan
            leader_tuples = 0
            for ptr, ends in leader.node_ends.items():
                for end in ends:
                    if 'Scan' in end.data.get('node_type', ''):
                        leader_tuples += end.data.get('tuples', 0)

            # Leader should NOT have all tuples (workers should have some)
            self.assertLess(leader_tuples, self.row_count,
                f"Leader should not have all {self.row_count} tuples (has {leader_tuples})")

            # Workers should have tuples
            worker_tuples = 0
            for worker in workers:
                for ptr, ends in worker.node_ends.items():
                    for end in ends:
                        if 'Scan' in end.data.get('node_type', ''):
                            worker_tuples += end.data.get('tuples', 0)

            self.assertGreater(worker_tuples, 0,
                "Workers should have captured some tuples")

        finally:
            control.close()


class TestParallelNodeTracking(unittest.TestCase):
    """Test node tracking in parallel workers."""

    @classmethod
    def setUpClass(cls):
        cls.harness = ParallelTestHarness()

        conn = cls.harness.new_connection()
        conn.execute("DROP TABLE IF EXISTS parallel_node_test CASCADE")
        conn.execute("""
            CREATE TABLE parallel_node_test (
                id SERIAL PRIMARY KEY,
                data TEXT
            )
        """)
        conn.execute("""
            INSERT INTO parallel_node_test (data)
            SELECT md5(i::text)
            FROM generate_series(1, 50000) i
        """)
        conn.execute("ANALYZE parallel_node_test")
        conn.close()

    @classmethod
    def tearDownClass(cls):
        try:
            conn = cls.harness.new_connection()
            conn.execute("DROP TABLE IF EXISTS parallel_node_test CASCADE")
            conn.close()
        except Exception:
            pass
        cls.harness.cleanup()

    def test_worker_nodes_paired(self):
        """Test that NODE_START/NODE_END are paired in worker traces."""
        self.harness.cleanup_traces()

        conn = self.harness.new_connection()
        control = self.harness.new_connection()

        try:
            control.execute(f"SELECT trace_10046.enable_trace({conn.pid})")
            self.harness.enable_parallel_query(conn, workers=2)

            conn.execute("SELECT count(*) FROM parallel_node_test")
            conn.close()
            time.sleep(0.5)

            trace_files = self.harness.get_all_trace_files()
            _, workers = self.harness.separate_leader_and_workers(trace_files)

            for worker in workers:
                # All nodes should be paired
                assert_all_nodes_paired(worker)

        finally:
            control.close()

    def test_worker_node_timing_valid(self):
        """Test that node timing is valid in worker traces."""
        self.harness.cleanup_traces()

        conn = self.harness.new_connection()
        control = self.harness.new_connection()

        try:
            control.execute(f"SELECT trace_10046.enable_trace({conn.pid})")
            self.harness.enable_parallel_query(conn, workers=2)

            conn.execute("SELECT count(*) FROM parallel_node_test")
            conn.close()
            time.sleep(0.5)

            trace_files = self.harness.get_all_trace_files()
            _, workers = self.harness.separate_leader_and_workers(trace_files)

            for worker in workers:
                assert_node_timing_valid(worker)

        finally:
            control.close()

    def test_worker_has_node_map(self):
        """Test that worker traces have NODE_MAP entries."""
        self.harness.cleanup_traces()

        conn = self.harness.new_connection()
        control = self.harness.new_connection()

        try:
            control.execute(f"SELECT trace_10046.enable_trace({conn.pid})")
            self.harness.enable_parallel_query(conn, workers=2)

            conn.execute("SELECT count(*) FROM parallel_node_test")
            conn.close()
            time.sleep(0.5)

            trace_files = self.harness.get_all_trace_files()
            _, workers = self.harness.separate_leader_and_workers(trace_files)

            for worker in workers:
                # Check for NODE_MAP events (plan nodes)
                with open(worker.path, 'r') as f:
                    has_node_map = any('NODE_MAP' in line for line in f)
                self.assertTrue(has_node_map,
                    f"Worker trace {worker.path} should have NODE_MAP entries")

        finally:
            control.close()


class TestParallelQueryVariants(unittest.TestCase):
    """Test parallel tracing with different query types."""

    @classmethod
    def setUpClass(cls):
        cls.harness = ParallelTestHarness()

        conn = cls.harness.new_connection()

        # Create tables for various parallel query scenarios
        conn.execute("DROP TABLE IF EXISTS parallel_agg_test CASCADE")
        conn.execute("DROP TABLE IF EXISTS parallel_sort_test CASCADE")

        conn.execute("""
            CREATE TABLE parallel_agg_test (
                id SERIAL PRIMARY KEY,
                category INTEGER,
                value NUMERIC
            )
        """)
        conn.execute("""
            INSERT INTO parallel_agg_test (category, value)
            SELECT i % 100, random() * 1000
            FROM generate_series(1, 100000) i
        """)

        conn.execute("""
            CREATE TABLE parallel_sort_test (
                id SERIAL PRIMARY KEY,
                data TEXT,
                sort_key INTEGER
            )
        """)
        conn.execute("""
            INSERT INTO parallel_sort_test (data, sort_key)
            SELECT md5(i::text), (random() * 1000000)::integer
            FROM generate_series(1, 100000) i
        """)

        conn.execute("ANALYZE parallel_agg_test")
        conn.execute("ANALYZE parallel_sort_test")
        conn.close()

    @classmethod
    def tearDownClass(cls):
        try:
            conn = cls.harness.new_connection()
            conn.execute("DROP TABLE IF EXISTS parallel_agg_test CASCADE")
            conn.execute("DROP TABLE IF EXISTS parallel_sort_test CASCADE")
            conn.close()
        except Exception:
            pass
        cls.harness.cleanup()

    def test_parallel_aggregate(self):
        """Test parallel aggregate query tracing."""
        self.harness.cleanup_traces()

        conn = self.harness.new_connection()
        control = self.harness.new_connection()

        try:
            control.execute(f"SELECT trace_10046.enable_trace({conn.pid})")
            self.harness.enable_parallel_query(conn, workers=4)

            # Parallel aggregate
            result = conn.execute("""
                SELECT category, SUM(value), AVG(value), COUNT(*)
                FROM parallel_agg_test
                GROUP BY category
            """)
            self.assertEqual(len(result.rows), 100)

            conn.close()
            time.sleep(0.5)

            trace_files = self.harness.get_all_trace_files()
            leader, workers = self.harness.separate_leader_and_workers(trace_files)

            self.assertIsNotNone(leader)
            # Should have workers for parallel aggregate
            self.assertGreater(len(workers), 0)

            for worker in workers:
                assert_all_nodes_paired(worker)

        finally:
            control.close()

    def test_parallel_sort(self):
        """Test parallel sort query tracing."""
        self.harness.cleanup_traces()

        conn = self.harness.new_connection()
        control = self.harness.new_connection()

        try:
            control.execute(f"SELECT trace_10046.enable_trace({conn.pid})")
            self.harness.enable_parallel_query(conn, workers=4)

            # Query that may use parallel sort
            conn.execute("""
                SELECT * FROM parallel_sort_test
                ORDER BY sort_key
                LIMIT 100
            """)

            conn.close()
            time.sleep(0.5)

            trace_files = self.harness.get_all_trace_files()
            leader, workers = self.harness.separate_leader_and_workers(trace_files)

            self.assertIsNotNone(leader)

            # Verify traces are valid
            assert_all_nodes_paired(leader)
            for worker in workers:
                assert_all_nodes_paired(worker)

        finally:
            control.close()


class TestNonParallelQuery(unittest.TestCase):
    """Test that non-parallel queries don't create worker traces."""

    @classmethod
    def setUpClass(cls):
        cls.harness = ParallelTestHarness()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def test_small_table_no_workers(self):
        """Test that small table queries don't spawn workers."""
        self.harness.cleanup_traces()

        conn = self.harness.new_connection()
        control = self.harness.new_connection()

        try:
            control.execute(f"SELECT trace_10046.enable_trace({conn.pid})")

            # Query on small system table (unlikely to parallelize)
            conn.execute("SELECT count(*) FROM pg_class WHERE relname = 'pg_class'")

            conn.close()
            time.sleep(0.5)

            trace_files = self.harness.get_all_trace_files()
            leader, workers = self.harness.separate_leader_and_workers(trace_files)

            self.assertIsNotNone(leader)
            # Should not have worker traces for this small query
            self.assertEqual(len(workers), 0,
                "Small query should not spawn parallel workers")

        finally:
            control.close()

    def test_parallel_disabled_no_workers(self):
        """Test that with parallel disabled, no worker traces are created."""
        self.harness.cleanup_traces()

        conn = self.harness.new_connection()
        control = self.harness.new_connection()

        try:
            control.execute(f"SELECT trace_10046.enable_trace({conn.pid})")

            # Explicitly disable parallel
            conn.execute("SET max_parallel_workers_per_gather = 0")

            conn.execute("SELECT count(*) FROM generate_series(1, 10000)")

            conn.close()
            time.sleep(0.5)

            trace_files = self.harness.get_all_trace_files()
            leader, workers = self.harness.separate_leader_and_workers(trace_files)

            self.assertIsNotNone(leader)
            self.assertEqual(len(workers), 0,
                "With parallel disabled, should not have worker traces")

        finally:
            control.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
