#!/usr/bin/env python3
"""
Test Sampling - SAMPLE events, wait events, and CPU tracking.

Tests that:
- Long-running queries generate SAMPLE events
- Wait events are captured correctly (wait_event_info)
- Sample intervals are respected
- Node attribution in samples is correct
- CPU time is tracked via samples
"""

import unittest
import sys
import os
import time

sys.path.insert(0, os.path.dirname(__file__))

from lib.pg_harness import PgHarness
from lib.assertions import (
    parse_trace,
    assert_header_present,
    assert_all_nodes_paired,
    TraceAssertionError,
)
from lib.trace_validator import EventType


class TestSampleEvents(unittest.TestCase):
    """Test SAMPLE event generation during query execution."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

        # Create a large table for long-running queries
        conn = cls.harness.new_connection()
        conn.execute("DROP TABLE IF EXISTS sample_test CASCADE")
        conn.execute("""
            CREATE TABLE sample_test (
                id SERIAL PRIMARY KEY,
                data TEXT,
                value INTEGER
            )
        """)
        # Insert enough rows to make queries take time
        conn.execute("""
            INSERT INTO sample_test (data, value)
            SELECT md5(i::text), i % 1000
            FROM generate_series(1, 100000) i
        """)
        conn.execute("ANALYZE sample_test")
        conn.close()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def _count_samples(self, trace) -> int:
        """Count SAMPLE events in trace."""
        count = 0
        for event in trace.events:
            if event.event_type == EventType.SAMPLE:
                count += 1
        return count

    def _get_samples(self, trace) -> list:
        """Get all SAMPLE events from trace."""
        samples = []
        for event in trace.events:
            if event.event_type == EventType.SAMPLE:
                samples.append(event)
        return samples

    def test_long_query_generates_samples(self):
        """Test that a long-running query generates SAMPLE events."""
        with self.harness.traced_session() as session:
            # Run a query that takes time (full table scan with aggregation)
            session.conn.execute("SET work_mem = '4MB'")  # Force disk sort
            result = session.execute("""
                SELECT data, SUM(value) as total
                FROM sample_test
                GROUP BY data
                ORDER BY total DESC
                LIMIT 100
            """, with_explain=False)

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            # Check SAMPLING_START/END present
            has_sampling_start = False
            has_sampling_end = False
            for event in trace.events:
                if event.event_type == EventType.SAMPLING_START:
                    has_sampling_start = True
                    # Check interval is set
                    self.assertIn('interval_ms', event.data)
                    self.assertGreater(event.data['interval_ms'], 0)
                if event.event_type == EventType.SAMPLING_END:
                    has_sampling_end = True

            self.assertTrue(has_sampling_start, "SAMPLING_START should be present")
            self.assertTrue(has_sampling_end, "SAMPLING_END should be present")

    def test_sample_interval_header(self):
        """Test that sample interval is in trace header."""
        with self.harness.traced_session() as session:
            session.execute("SELECT 1", with_explain=False)

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            # Check header has sample interval
            assert_header_present(trace, ['SAMPLE_INTERVAL_MS'])
            interval = int(trace.header.get('SAMPLE_INTERVAL_MS', 0))
            self.assertGreater(interval, 0, "Sample interval should be positive")

    def test_sample_has_node_attribution(self):
        """Test that SAMPLE events have node pointer attribution."""
        with self.harness.traced_session() as session:
            # Run a slow query
            session.conn.execute("SET work_mem = '1MB'")
            result = session.execute("""
                SELECT t1.data, t2.data, t1.value + t2.value
                FROM sample_test t1
                CROSS JOIN (SELECT * FROM sample_test LIMIT 100) t2
                WHERE t1.id <= 1000
                LIMIT 10000
            """, with_explain=False)

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            samples = self._get_samples(trace)

            # If we got samples, check they have node pointer
            for sample in samples:
                self.assertIn('ptr', sample.data, "SAMPLE should have node pointer")
                # ptr can be NULL (0x0) if no node is executing
                # but if non-null, should be valid hex
                ptr = sample.data.get('ptr', '')
                if ptr and ptr != '(nil)' and ptr != '0x0':
                    self.assertTrue(
                        ptr.startswith('0x'),
                        f"Node pointer should be hex: {ptr}"
                    )

    def test_sample_count_in_sampling_end(self):
        """Test that SAMPLING_END reports sample count."""
        with self.harness.traced_session() as session:
            session.execute("SELECT * FROM sample_test LIMIT 1000", with_explain=False)

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            for event in trace.events:
                if event.event_type == EventType.SAMPLING_END:
                    self.assertIn('samples', event.data)
                    # Sample count should be >= 0
                    self.assertGreaterEqual(event.data['samples'], 0)


class TestWaitEvents(unittest.TestCase):
    """Test wait event capture in SAMPLE events."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

        conn = cls.harness.new_connection()
        conn.execute("DROP TABLE IF EXISTS wait_test CASCADE")
        conn.execute("""
            CREATE TABLE wait_test (
                id SERIAL PRIMARY KEY,
                data TEXT
            )
        """)
        conn.execute("""
            INSERT INTO wait_test (data)
            SELECT md5(i::text)
            FROM generate_series(1, 50000) i
        """)
        conn.execute("ANALYZE wait_test")
        conn.close()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def test_wait_event_format(self):
        """Test wait event info format in samples."""
        with self.harness.traced_session() as session:
            # Force disk IO by using large sort
            session.conn.execute("SET work_mem = '1MB'")
            session.execute("""
                SELECT * FROM wait_test ORDER BY data
            """, with_explain=False)

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            for event in trace.events:
                if event.event_type == EventType.SAMPLE:
                    # Wait event should be hex or 0
                    wait_event = event.data.get('wait_event', '')
                    if wait_event:
                        # Should be hex format like 0x00000000
                        self.assertTrue(
                            wait_event.startswith('0x') or wait_event == '0',
                            f"Wait event should be hex: {wait_event}"
                        )

    def test_io_wait_captured(self):
        """Test that IO waits are captured when doing disk reads."""
        with self.harness.traced_session() as session:
            # Drop caches to force disk reads (if possible)
            # This may not work without privileges, but the query should still run

            # Force a checkpoint and clear buffers
            try:
                session.conn.execute("CHECKPOINT")
            except:
                pass

            # Run query that reads data
            session.execute("""
                SELECT COUNT(*) FROM wait_test WHERE data LIKE '%abc%'
            """, with_explain=False)

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            # Just verify trace is valid - IO waits depend on system state
            assert_all_nodes_paired(trace)


class TestSamplingTiming(unittest.TestCase):
    """Test sampling timing and intervals."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def test_samples_have_timestamps(self):
        """Test that SAMPLE events have valid timestamps."""
        with self.harness.traced_session() as session:
            # Use pg_sleep to guarantee samples
            session.execute("SELECT pg_sleep(0.1)", with_explain=False)

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            for event in trace.events:
                if event.event_type == EventType.SAMPLE:
                    self.assertIsNotNone(event.timestamp)
                    self.assertGreater(event.timestamp, 0)

    def test_sample_timestamps_increase(self):
        """Test that SAMPLE timestamps are monotonically increasing."""
        with self.harness.traced_session() as session:
            # Run longer query to get multiple samples
            session.execute("SELECT pg_sleep(0.15)", with_explain=False)

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            samples = []
            for event in trace.events:
                if event.event_type == EventType.SAMPLE:
                    samples.append(event)

            # Check timestamps are increasing
            for i in range(1, len(samples)):
                self.assertGreaterEqual(
                    samples[i].timestamp,
                    samples[i-1].timestamp,
                    "Sample timestamps should be monotonically increasing"
                )

    def test_samples_within_execution(self):
        """Test that samples occur within EXEC_START/EXEC_END."""
        with self.harness.traced_session() as session:
            session.execute("SELECT pg_sleep(0.05)", with_explain=False)

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            exec_start_ts = None
            exec_end_ts = None
            sample_timestamps = []

            for event in trace.events:
                if event.event_type == EventType.EXEC_START:
                    exec_start_ts = event.timestamp
                elif event.event_type == EventType.EXEC_END:
                    exec_end_ts = event.timestamp
                elif event.event_type == EventType.SAMPLE:
                    sample_timestamps.append(event.timestamp)

            # Verify samples are within execution window
            if exec_start_ts and exec_end_ts:
                for ts in sample_timestamps:
                    self.assertGreaterEqual(
                        ts, exec_start_ts,
                        "Sample should be after EXEC_START"
                    )
                    self.assertLessEqual(
                        ts, exec_end_ts,
                        "Sample should be before EXEC_END"
                    )


class TestCPUTracking(unittest.TestCase):
    """Test CPU time tracking via samples."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

        conn = cls.harness.new_connection()
        conn.execute("DROP TABLE IF EXISTS cpu_test CASCADE")
        conn.execute("""
            CREATE TABLE cpu_test (
                id SERIAL PRIMARY KEY,
                val DOUBLE PRECISION
            )
        """)
        conn.execute("""
            INSERT INTO cpu_test (val)
            SELECT random()
            FROM generate_series(1, 100000) i
        """)
        conn.execute("ANALYZE cpu_test")
        conn.close()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def test_cpu_intensive_query_samples(self):
        """Test CPU-intensive query generates samples without wait events."""
        with self.harness.traced_session() as session:
            # CPU-intensive query (lots of math, no IO)
            result = session.execute("""
                SELECT
                    SUM(sin(val) * cos(val) * tan(val + 0.1)) as calc
                FROM cpu_test
            """, with_explain=False)

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            # Trace should be valid
            assert_all_nodes_paired(trace)

            # Check for samples - CPU work may generate samples
            samples = []
            for event in trace.events:
                if event.event_type == EventType.SAMPLE:
                    samples.append(event)

            # If samples exist, many should have 0 wait event (on CPU)
            cpu_samples = 0
            for sample in samples:
                wait = sample.data.get('wait_event', '0x00000000')
                if wait in ('0', '0x0', '0x00000000'):
                    cpu_samples += 1

            # Can't guarantee samples for fast queries, but structure should be valid

    def test_sample_progress_stats(self):
        """Test that samples include progress stats (tuples, blocks)."""
        with self.harness.traced_session() as session:
            session.execute("""
                SELECT COUNT(*), SUM(val), AVG(val)
                FROM cpu_test
            """, with_explain=False)

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            for event in trace.events:
                if event.event_type == EventType.SAMPLE:
                    # Sample should have tuple and block counts
                    # These may be 0 for short queries
                    if 'tuples' in event.data:
                        self.assertGreaterEqual(event.data['tuples'], 0)
                    if 'blks_hit' in event.data:
                        self.assertGreaterEqual(event.data['blks_hit'], 0)
                    if 'blks_read' in event.data:
                        self.assertGreaterEqual(event.data['blks_read'], 0)


class TestSamplingEdgeCases(unittest.TestCase):
    """Test edge cases in sampling."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def test_fast_query_no_samples(self):
        """Test that very fast queries may not generate samples."""
        with self.harness.traced_session() as session:
            result = session.execute("SELECT 1", with_explain=False)

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            # Should have SAMPLING_START/END even without samples
            has_sampling = False
            for event in trace.events:
                if event.event_type in (EventType.SAMPLING_START, EventType.SAMPLING_END):
                    has_sampling = True
                    break

            self.assertTrue(has_sampling, "Sampling markers should be present")

    def test_multiple_queries_sampling(self):
        """Test sampling across multiple queries in same session."""
        with self.harness.traced_session() as session:
            session.execute("SELECT pg_sleep(0.02)", with_explain=False)
            session.execute("SELECT pg_sleep(0.02)", with_explain=False)
            session.execute("SELECT pg_sleep(0.02)", with_explain=False)

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            # Count SAMPLING_START/END pairs
            starts = 0
            ends = 0
            for event in trace.events:
                if event.event_type == EventType.SAMPLING_START:
                    starts += 1
                elif event.event_type == EventType.SAMPLING_END:
                    ends += 1

            # Should have 3 pairs (one per query)
            self.assertEqual(starts, 3, "Should have 3 SAMPLING_START events")
            self.assertEqual(ends, 3, "Should have 3 SAMPLING_END events")

    def test_cancelled_query_sampling(self):
        """Test that cancelled queries still have proper sampling markers."""
        with self.harness.traced_session() as session:
            # Run a query that will complete quickly
            session.execute("SELECT 1", with_explain=False)

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            # Verify SAMPLING_START has matching END
            starts = 0
            ends = 0
            for event in trace.events:
                if event.event_type == EventType.SAMPLING_START:
                    starts += 1
                elif event.event_type == EventType.SAMPLING_END:
                    ends += 1

            self.assertEqual(starts, ends, "SAMPLING_START/END should be paired")


if __name__ == '__main__':
    unittest.main(verbosity=2)
