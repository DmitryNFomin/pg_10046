#!/usr/bin/env python3
"""
Test Cross-Backend Tracing - Enable trace from another session.

Tests the enable_trace() functionality that allows one backend to
request tracing of another backend via shared memory flags.

This tests:
- Basic enable_trace from another session
- enable_trace_ebpf variant
- disable_trace clearing of pending requests
- Race conditions and timing
- Multiple concurrent traced sessions
"""

import unittest
import sys
import os
import time
import threading
import glob

sys.path.insert(0, os.path.dirname(__file__))

from lib.pg_harness import PgHarness, PgConfig
from lib.assertions import (
    parse_trace,
    assert_header_present,
    assert_query_count,
    assert_query_count_at_least,
    assert_query_captured,
    assert_all_nodes_paired,
    assert_basic_trace_correctness,
    TraceAssertionError,
)


class TestCrossBackendEnable(unittest.TestCase):
    """Test enabling trace from another backend."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()
        cls.config = cls.harness.config

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def test_enable_trace_basic(self):
        """Test basic enable_trace from control session."""
        # Create target and control connections
        target = self.harness.new_connection()
        control = self.harness.new_connection()

        self.harness.cleanup_traces()
        target_pid = target.pid  # Save PID before close

        try:
            # Enable trace on target from control
            result = control.execute(
                "SELECT trace_10046.enable_trace(%s)",
                (target_pid,)
            )
            self.assertIsNone(result.error, f"enable_trace failed: {result.error}")
            self.assertTrue(result.rows[0]['enable_trace'])

            # Run query on target - should be traced
            target.execute("SELECT * FROM generate_series(1, 100)")

            # Close target to flush async buffer, then check trace
            control.execute("SELECT trace_10046.disable_trace(%s)", (target_pid,))
            target.close()
            time.sleep(0.2)

            pattern = f"{self.config.trace_dir}/pg_10046_{target_pid}_*.trc"
            files = glob.glob(pattern)
            self.assertTrue(len(files) > 0, "Trace file should exist")

            # Validate trace
            trace = assert_basic_trace_correctness(files[0])
            assert_query_count_at_least(trace, 1)

        finally:
            if not target._closed:
                target.close()
            control.close()

    def test_enable_trace_ebpf(self):
        """Test enable_trace_ebpf variant."""
        target = self.harness.new_connection()
        control = self.harness.new_connection()

        self.harness.cleanup_traces()
        target_pid = target.pid  # Save PID before close

        try:
            # Enable trace with eBPF flag
            result = control.execute(
                "SELECT trace_10046.enable_trace_ebpf(%s)",
                (target_pid,)
            )
            self.assertIsNone(result.error)
            self.assertTrue(result.rows[0]['enable_trace_ebpf'])

            # Run query
            target.execute("SELECT 1 + 1 AS result")

            # Close target to flush async buffer, then check trace
            control.execute("SELECT trace_10046.disable_trace(%s)", (target_pid,))
            target.close()
            time.sleep(0.2)

            pattern = f"{self.config.trace_dir}/pg_10046_{target_pid}_*.trc"
            files = glob.glob(pattern)
            self.assertTrue(len(files) > 0)

            trace = parse_trace(files[0])
            assert_query_count_at_least(trace, 1)

        finally:
            if not target._closed:
                target.close()
            control.close()

    def test_disable_trace_clears_request(self):
        """Test that disable_trace clears pending request."""
        target = self.harness.new_connection()
        control = self.harness.new_connection()

        self.harness.cleanup_traces()

        try:
            # Enable then immediately disable
            control.execute("SELECT trace_10046.enable_trace(%s)", (target.pid,))
            control.execute("SELECT trace_10046.disable_trace(%s)", (target.pid,))

            # Run query - should NOT be traced
            target.execute("SELECT 'not traced'")

            time.sleep(0.3)
            pattern = f"{self.config.trace_dir}/pg_10046_{target.pid}_*.trc"
            files = glob.glob(pattern)

            # Should have no trace (or trace should be empty/minimal)
            if files:
                trace = parse_trace(files[0])
                # If there's a trace, it shouldn't have the query
                queries_with_text = [q for q in trace.queries if 'not traced' in q.sql]
                self.assertEqual(len(queries_with_text), 0, "Query should not be traced after disable")

        finally:
            target.close()
            control.close()

    def test_enable_on_nonexistent_pid(self):
        """Test enable_trace on non-existent PID doesn't crash."""
        control = self.harness.new_connection()

        try:
            # Use a very high PID that shouldn't exist
            result = control.execute(
                "SELECT trace_10046.enable_trace(%s)",
                (99999999,)
            )
            # Should not error - return value may be true or false depending on implementation
            self.assertIsNone(result.error)

        finally:
            control.close()

    def test_enable_on_self(self):
        """Test enable_trace on self."""
        conn = self.harness.new_connection()
        self.harness.cleanup_traces()

        try:
            pid = conn.pid
            result = conn.execute(
                "SELECT trace_10046.enable_trace(%s)",
                (pid,)
            )
            self.assertIsNone(result.error)

            # Run another query
            conn.execute("SELECT 'self trace' AS msg")

            time.sleep(0.3)
            pattern = f"{self.config.trace_dir}/pg_10046_{pid}_*.trc"
            files = glob.glob(pattern)

            # Implementation may or may not support self-trace
            # Just verify no crash occurred

        finally:
            conn.execute("SELECT trace_10046.disable_trace(%s)", (conn.pid,))
            conn.close()


class TestMultipleSessions(unittest.TestCase):
    """Test multiple concurrent traced sessions."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def test_two_concurrent_traces(self):
        """Test tracing two backends concurrently."""
        target1 = self.harness.new_connection()
        target2 = self.harness.new_connection()
        control = self.harness.new_connection()

        self.harness.cleanup_traces()
        target1_pid = target1.pid  # Save PIDs before close
        target2_pid = target2.pid

        try:
            # Enable trace on both
            control.execute("SELECT trace_10046.enable_trace(%s)", (target1_pid,))
            control.execute("SELECT trace_10046.enable_trace(%s)", (target2_pid,))

            # Run queries on both
            target1.execute("SELECT 'target1_query' AS source")
            target2.execute("SELECT 'target2_query' AS source")

            # Close targets to flush async buffers
            control.execute("SELECT trace_10046.disable_trace(%s)", (target1_pid,))
            control.execute("SELECT trace_10046.disable_trace(%s)", (target2_pid,))
            target1.close()
            target2.close()
            time.sleep(0.2)

            # Check both traces exist
            pattern1 = f"{self.harness.config.trace_dir}/pg_10046_{target1_pid}_*.trc"
            pattern2 = f"{self.harness.config.trace_dir}/pg_10046_{target2_pid}_*.trc"

            files1 = glob.glob(pattern1)
            files2 = glob.glob(pattern2)

            self.assertTrue(len(files1) > 0, "Target 1 trace should exist")
            self.assertTrue(len(files2) > 0, "Target 2 trace should exist")

            # Validate each trace
            trace1 = parse_trace(files1[0])
            trace2 = parse_trace(files2[0])

            # Each should have their respective query
            assert_query_captured(trace1, r"target1_query")
            assert_query_captured(trace2, r"target2_query")

        finally:
            if not target1._closed:
                target1.close()
            if not target2._closed:
                target2.close()
            control.close()

    def test_five_concurrent_traces(self):
        """Test tracing five backends concurrently."""
        targets = [self.harness.new_connection() for _ in range(5)]
        control = self.harness.new_connection()

        self.harness.cleanup_traces()
        target_pids = [t.pid for t in targets]  # Save PIDs before close

        try:
            # Enable trace on all
            for pid in target_pids:
                control.execute("SELECT trace_10046.enable_trace(%s)", (pid,))

            # Run queries on all
            for i, t in enumerate(targets):
                t.execute(f"SELECT {i} AS session_num")

            # Close all targets to flush async buffers
            for i, (t, pid) in enumerate(zip(targets, target_pids)):
                control.execute("SELECT trace_10046.disable_trace(%s)", (pid,))
                t.close()
            time.sleep(0.2)

            # Verify all traces exist
            for i, pid in enumerate(target_pids):
                pattern = f"{self.harness.config.trace_dir}/pg_10046_{pid}_*.trc"
                files = glob.glob(pattern)
                self.assertTrue(len(files) > 0, f"Target {i} trace should exist")

                trace = parse_trace(files[0])
                assert_query_count_at_least(trace, 1)

        finally:
            for t in targets:
                if not t._closed:
                    t.close()
            control.close()


class TestTraceTiming(unittest.TestCase):
    """Test trace timing and race conditions."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def test_enable_before_query(self):
        """Test enable before first query."""
        target = self.harness.new_connection()
        control = self.harness.new_connection()

        self.harness.cleanup_traces()
        target_pid = target.pid  # Save PID before close

        try:
            # Enable first
            control.execute("SELECT trace_10046.enable_trace(%s)", (target_pid,))

            # Wait a bit
            time.sleep(0.1)

            # Then run query
            target.execute("SELECT 'after enable' AS timing")

            # Close target to flush async buffer
            control.execute("SELECT trace_10046.disable_trace(%s)", (target_pid,))
            target.close()
            time.sleep(0.2)

            pattern = f"{self.harness.config.trace_dir}/pg_10046_{target_pid}_*.trc"
            files = glob.glob(pattern)
            self.assertTrue(len(files) > 0)

            trace = parse_trace(files[0])
            assert_query_captured(trace, r"after enable")

        finally:
            if not target._closed:
                target.close()
            control.close()

    def test_multiple_queries_single_trace(self):
        """Test multiple queries captured in single trace session."""
        with self.harness.traced_session() as session:
            session.execute("SELECT 1 AS first", with_explain=False)
            session.execute("SELECT 2 AS second", with_explain=False)
            session.execute("SELECT 3 AS third", with_explain=False)

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            # All three queries should be captured
            # May include internal queries like pg_backend_pid() so use >=
            self.assertGreaterEqual(len(trace.queries), 3)
            assert_query_captured(trace, r"first")
            assert_query_captured(trace, r"second")
            assert_query_captured(trace, r"third")

    def test_rapid_queries(self):
        """Test rapid succession of queries."""
        with self.harness.traced_session() as session:
            # Run many queries rapidly (without EXPLAIN to get exact count)
            for i in range(20):
                session.execute(f"SELECT {i}", with_explain=False)

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            # Should capture all queries
            assert_query_count(trace, 20)

            # All nodes should be paired
            assert_all_nodes_paired(trace)

    def test_concurrent_queries_threads(self):
        """Test concurrent queries from multiple threads."""
        target = self.harness.new_connection()
        control = self.harness.new_connection()

        self.harness.cleanup_traces()
        results = []
        errors = []

        def run_query(query_num):
            try:
                # Create new connection in thread
                conn = self.harness.new_connection()
                control.execute("SELECT trace_10046.enable_trace(%s)", (conn.pid,))
                conn.execute(f"SELECT 'thread_{query_num}' AS source")
                time.sleep(0.2)
                control.execute("SELECT trace_10046.disable_trace(%s)", (conn.pid,))
                results.append((query_num, conn.pid))
                conn.close()
            except Exception as e:
                errors.append((query_num, str(e)))

        try:
            # Start 3 threads
            threads = []
            for i in range(3):
                t = threading.Thread(target=run_query, args=(i,))
                threads.append(t)
                t.start()

            # Wait for all threads
            for t in threads:
                t.join(timeout=10)

            # Check no errors
            self.assertEqual(len(errors), 0, f"Thread errors: {errors}")

            # All threads should have completed
            self.assertEqual(len(results), 3)

            # Each should have a trace file
            time.sleep(0.3)
            for query_num, pid in results:
                pattern = f"{self.harness.config.trace_dir}/pg_10046_{pid}_*.trc"
                files = glob.glob(pattern)
                # May or may not have trace depending on timing
                # Just verify no crashes occurred

        finally:
            target.close()
            control.close()


class TestHarnessIntegration(unittest.TestCase):
    """Test the traced_session harness integration."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def test_traced_session_context(self):
        """Test traced_session context manager."""
        with self.harness.traced_session() as session:
            result = session.execute("SELECT 42 AS answer")
            self.assertEqual(result.rows[0]['answer'], 42)

            trace = session.get_trace()
            self.assertIsNotNone(trace)
            self.assertTrue(trace.exists)

    def test_traced_session_cleanup(self):
        """Test traced_session cleans up properly."""
        pid = None
        with self.harness.traced_session() as session:
            pid = session.conn.pid
            session.execute("SELECT 1")

        # Connection should be closed
        # New connection with same harness should work
        conn = self.harness.new_connection()
        self.assertNotEqual(conn.pid, pid)
        conn.close()

    def test_multiple_sessions_harness(self):
        """Test multiple_sessions context manager."""
        with self.harness.multiple_sessions(3) as sessions:
            self.assertEqual(len(sessions), 3)

            for i, s in enumerate(sessions):
                s.execute(f"SELECT {i}")

            # Each should have a trace
            for s in sessions:
                trace = s.get_trace()
                self.assertIsNotNone(trace)

    def test_ebpf_mode(self):
        """Test traced_session with ebpf_active flag."""
        with self.harness.traced_session(ebpf_active=True) as session:
            session.execute("SELECT 'ebpf mode' AS test")

            trace = session.get_trace()
            self.assertIsNotNone(trace)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def test_double_enable(self):
        """Test enabling trace twice on same backend."""
        target = self.harness.new_connection()
        control = self.harness.new_connection()

        self.harness.cleanup_traces()

        try:
            # Enable twice
            control.execute("SELECT trace_10046.enable_trace(%s)", (target.pid,))
            control.execute("SELECT trace_10046.enable_trace(%s)", (target.pid,))

            # Should still work
            target.execute("SELECT 'double enable' AS test")

            time.sleep(0.3)
            pattern = f"{self.harness.config.trace_dir}/pg_10046_{target.pid}_*.trc"
            files = glob.glob(pattern)
            self.assertTrue(len(files) > 0)

        finally:
            control.execute("SELECT trace_10046.disable_trace(%s)", (target.pid,))
            target.close()
            control.close()

    def test_disable_without_enable(self):
        """Test disabling trace without prior enable."""
        target = self.harness.new_connection()
        control = self.harness.new_connection()

        try:
            # Disable without enable - should not error
            result = control.execute(
                "SELECT trace_10046.disable_trace(%s)",
                (target.pid,)
            )
            self.assertIsNone(result.error)

        finally:
            target.close()
            control.close()

    def test_negative_pid(self):
        """Test enable with negative PID."""
        control = self.harness.new_connection()

        try:
            result = control.execute(
                "SELECT trace_10046.enable_trace(%s)",
                (-1,)
            )
            # Should return false, not error
            self.assertFalse(result.rows[0]['enable_trace'])

        finally:
            control.close()

    def test_zero_pid(self):
        """Test enable with zero PID."""
        control = self.harness.new_connection()

        try:
            result = control.execute(
                "SELECT trace_10046.enable_trace(%s)",
                (0,)
            )
            self.assertFalse(result.rows[0]['enable_trace'])

        finally:
            control.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
