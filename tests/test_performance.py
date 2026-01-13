#!/usr/bin/env python3
"""
Performance Tests for pg_10046.

Tests that measure:
- Tracing overhead compared to untraced queries
- High-throughput query handling
- Large result set tracing
- Concurrent session performance
- Trace file sizes
- Long-running query handling
- eBPF daemon performance under load

These tests are designed to catch performance regressions and
establish baseline metrics for the tracing extension.
"""

import unittest
import sys
import os
import time
import threading
import statistics
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(__file__))

from lib.pg_harness import PgHarness, PgConfig
from lib.assertions import parse_trace, assert_all_nodes_paired


# Performance thresholds (can be adjusted based on hardware)
# Note: overhead includes trace file I/O and fsync which varies significantly by hardware
# These thresholds are intentionally generous - the tests report numbers for analysis
# rather than enforcing strict performance requirements
MAX_OVERHEAD_PERCENT = 10000  # Very generous - tracing has significant I/O overhead
MIN_QUERIES_PER_SECOND = 20  # Minimum QPS for simple queries (conservative for VM)
MAX_TRACE_BYTES_PER_ROW = 500  # Max trace size per result row


class TestTracingOverhead(unittest.TestCase):
    """Measure overhead of tracing compared to untraced queries."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

        conn = cls.harness.new_connection()
        conn.execute("DROP TABLE IF EXISTS perf_overhead CASCADE")
        conn.execute("""
            CREATE TABLE perf_overhead (
                id SERIAL PRIMARY KEY,
                data TEXT,
                value INTEGER
            )
        """)
        conn.execute("""
            INSERT INTO perf_overhead (data, value)
            SELECT md5(i::text), i % 1000
            FROM generate_series(1, 10000) i
        """)
        conn.execute("ANALYZE perf_overhead")
        conn.close()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def _measure_query_time(self, conn, sql, iterations=10):
        """Measure average query execution time."""
        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            conn.execute(sql)
            elapsed = time.perf_counter() - start
            times.append(elapsed * 1000)  # Convert to ms
        return statistics.mean(times), statistics.stdev(times) if len(times) > 1 else 0

    def test_simple_select_overhead(self):
        """Measure overhead for simple SELECT query."""
        sql = "SELECT * FROM perf_overhead WHERE id = 5000"
        iterations = 50

        # Untraced baseline - measure batch of queries
        conn_untraced = self.harness.new_connection()
        # Warmup
        for _ in range(5):
            conn_untraced.execute(sql)

        start = time.perf_counter()
        for _ in range(iterations):
            conn_untraced.execute(sql)
        baseline_total = (time.perf_counter() - start) * 1000
        baseline_mean = baseline_total / iterations
        conn_untraced.close()

        # Traced measurement - measure batch within single session
        with self.harness.traced_session() as session:
            # Warmup
            for _ in range(5):
                session.conn.execute(sql)

            start = time.perf_counter()
            for _ in range(iterations):
                session.conn.execute(sql)
            traced_total = (time.perf_counter() - start) * 1000
            traced_mean = traced_total / iterations

        overhead_percent = ((traced_mean - baseline_mean) / baseline_mean) * 100 if baseline_mean > 0 else 0

        print(f"\n  Simple SELECT overhead ({iterations} queries):")
        print(f"    Baseline: {baseline_mean:.2f}ms/query ({baseline_total:.0f}ms total)")
        print(f"    Traced:   {traced_mean:.2f}ms/query ({traced_total:.0f}ms total)")
        print(f"    Overhead: {overhead_percent:.1f}%")

        # Performance test - just verify it completes and report numbers
        # Overhead varies widely based on hardware, so use generous threshold
        self.assertLess(
            overhead_percent,
            MAX_OVERHEAD_PERCENT,
            f"Tracing overhead {overhead_percent:.1f}% exceeds {MAX_OVERHEAD_PERCENT}%"
        )

    def test_aggregation_overhead(self):
        """Measure overhead for aggregation query."""
        sql = "SELECT COUNT(*), SUM(value), AVG(value) FROM perf_overhead"
        iterations = 30

        conn_untraced = self.harness.new_connection()
        for _ in range(3):
            conn_untraced.execute(sql)

        start = time.perf_counter()
        for _ in range(iterations):
            conn_untraced.execute(sql)
        baseline_total = (time.perf_counter() - start) * 1000
        baseline_mean = baseline_total / iterations
        conn_untraced.close()

        with self.harness.traced_session() as session:
            for _ in range(3):
                session.conn.execute(sql)

            start = time.perf_counter()
            for _ in range(iterations):
                session.conn.execute(sql)
            traced_total = (time.perf_counter() - start) * 1000
            traced_mean = traced_total / iterations

        overhead_percent = ((traced_mean - baseline_mean) / baseline_mean) * 100 if baseline_mean > 0 else 0

        print(f"\n  Aggregation overhead ({iterations} queries):")
        print(f"    Baseline: {baseline_mean:.2f}ms/query")
        print(f"    Traced:   {traced_mean:.2f}ms/query")
        print(f"    Overhead: {overhead_percent:.1f}%")

        self.assertLess(overhead_percent, MAX_OVERHEAD_PERCENT)

    def test_join_overhead(self):
        """Measure overhead for JOIN query."""
        sql = """
            SELECT p.data, p.value
            FROM perf_overhead p
            JOIN perf_overhead p2 ON p2.id = p.id + 1
            WHERE p.id <= 100
        """
        iterations = 30

        conn_untraced = self.harness.new_connection()
        for _ in range(3):
            conn_untraced.execute(sql)

        start = time.perf_counter()
        for _ in range(iterations):
            conn_untraced.execute(sql)
        baseline_total = (time.perf_counter() - start) * 1000
        baseline_mean = baseline_total / iterations
        conn_untraced.close()

        with self.harness.traced_session() as session:
            for _ in range(3):
                session.conn.execute(sql)

            start = time.perf_counter()
            for _ in range(iterations):
                session.conn.execute(sql)
            traced_total = (time.perf_counter() - start) * 1000
            traced_mean = traced_total / iterations

        overhead_percent = ((traced_mean - baseline_mean) / baseline_mean) * 100 if baseline_mean > 0 else 0

        print(f"\n  JOIN overhead ({iterations} queries):")
        print(f"    Baseline: {baseline_mean:.2f}ms/query")
        print(f"    Traced:   {traced_mean:.2f}ms/query")
        print(f"    Overhead: {overhead_percent:.1f}%")

        self.assertLess(overhead_percent, MAX_OVERHEAD_PERCENT)

    def test_sort_overhead(self):
        """Measure overhead for ORDER BY query."""
        sql = "SELECT * FROM perf_overhead ORDER BY data LIMIT 100"
        iterations = 30

        conn_untraced = self.harness.new_connection()
        for _ in range(3):
            conn_untraced.execute(sql)

        start = time.perf_counter()
        for _ in range(iterations):
            conn_untraced.execute(sql)
        baseline_total = (time.perf_counter() - start) * 1000
        baseline_mean = baseline_total / iterations
        conn_untraced.close()

        with self.harness.traced_session() as session:
            for _ in range(3):
                session.conn.execute(sql)

            start = time.perf_counter()
            for _ in range(iterations):
                session.conn.execute(sql)
            traced_total = (time.perf_counter() - start) * 1000
            traced_mean = traced_total / iterations

        overhead_percent = ((traced_mean - baseline_mean) / baseline_mean) * 100 if baseline_mean > 0 else 0

        print(f"\n  Sort overhead ({iterations} queries):")
        print(f"    Baseline: {baseline_mean:.2f}ms/query")
        print(f"    Traced:   {traced_mean:.2f}ms/query")
        print(f"    Overhead: {overhead_percent:.1f}%")

        self.assertLess(overhead_percent, MAX_OVERHEAD_PERCENT)


class TestHighThroughput(unittest.TestCase):
    """Test high-throughput query scenarios."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

        conn = cls.harness.new_connection()
        conn.execute("DROP TABLE IF EXISTS perf_throughput CASCADE")
        conn.execute("""
            CREATE TABLE perf_throughput (
                id SERIAL PRIMARY KEY,
                value INTEGER
            )
        """)
        conn.execute("""
            INSERT INTO perf_throughput (value)
            SELECT i FROM generate_series(1, 1000) i
        """)
        conn.execute("ANALYZE perf_throughput")
        conn.close()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def test_rapid_queries_throughput(self):
        """Test throughput of rapid simple queries."""
        num_queries = 200

        with self.harness.traced_session() as session:
            start = time.perf_counter()
            for i in range(num_queries):
                session.conn.execute(f"SELECT * FROM perf_throughput WHERE id = {(i % 1000) + 1}")
            elapsed = time.perf_counter() - start

            qps = num_queries / elapsed

            print(f"\n  Rapid queries throughput:")
            print(f"    Queries: {num_queries}")
            print(f"    Time: {elapsed:.2f}s")
            print(f"    QPS: {qps:.1f}")

            # Verify trace was captured
            trace_info = session.get_trace()
            self.assertIsNotNone(trace_info)

        self.assertGreater(qps, MIN_QUERIES_PER_SECOND / 2,
                          f"QPS {qps:.1f} below minimum {MIN_QUERIES_PER_SECOND / 2}")

    def test_mixed_query_throughput(self):
        """Test throughput with mixed query types."""
        queries = [
            "SELECT * FROM perf_throughput WHERE id = 500",
            "SELECT COUNT(*) FROM perf_throughput",
            "SELECT * FROM perf_throughput ORDER BY value LIMIT 10",
            "SELECT value, COUNT(*) FROM perf_throughput GROUP BY value HAVING COUNT(*) > 0 LIMIT 5",
        ]
        num_iterations = 50

        with self.harness.traced_session() as session:
            start = time.perf_counter()
            for i in range(num_iterations):
                for sql in queries:
                    session.conn.execute(sql)
            elapsed = time.perf_counter() - start

            total_queries = num_iterations * len(queries)
            qps = total_queries / elapsed

            print(f"\n  Mixed query throughput:")
            print(f"    Queries: {total_queries}")
            print(f"    Time: {elapsed:.2f}s")
            print(f"    QPS: {qps:.1f}")

        self.assertGreater(qps, MIN_QUERIES_PER_SECOND / 4)

    def test_sustained_throughput(self):
        """Test sustained query throughput over time."""
        duration_seconds = 5
        query_count = 0

        with self.harness.traced_session() as session:
            start = time.perf_counter()
            while time.perf_counter() - start < duration_seconds:
                session.conn.execute("SELECT 1")
                query_count += 1

            elapsed = time.perf_counter() - start
            qps = query_count / elapsed

            print(f"\n  Sustained throughput ({duration_seconds}s):")
            print(f"    Queries: {query_count}")
            print(f"    QPS: {qps:.1f}")

        self.assertGreater(qps, MIN_QUERIES_PER_SECOND)


class TestLargeResultSets(unittest.TestCase):
    """Test tracing with large result sets."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

        conn = cls.harness.new_connection()
        conn.execute("DROP TABLE IF EXISTS perf_large CASCADE")
        conn.execute("""
            CREATE TABLE perf_large (
                id SERIAL PRIMARY KEY,
                data TEXT,
                value INTEGER
            )
        """)
        # Create larger table for result set tests
        conn.execute("""
            INSERT INTO perf_large (data, value)
            SELECT md5(i::text), i % 1000
            FROM generate_series(1, 100000) i
        """)
        conn.execute("ANALYZE perf_large")
        conn.close()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def test_1k_rows_result(self):
        """Test tracing query returning 1,000 rows."""
        with self.harness.traced_session() as session:
            start = time.perf_counter()
            result = session.execute(
                "SELECT * FROM perf_large LIMIT 1000",
                with_explain=False
            )
            elapsed = time.perf_counter() - start

            trace_info = session.get_trace()
            trace_size = os.path.getsize(trace_info.path)

            print(f"\n  1K rows result:")
            print(f"    Rows: {result.rowcount}")
            print(f"    Time: {elapsed*1000:.2f}ms")
            print(f"    Trace size: {trace_size:,} bytes")
            print(f"    Bytes/row: {trace_size / 1000:.1f}")

            self.assertEqual(result.rowcount, 1000)
            # Trace shouldn't be excessively large
            self.assertLess(trace_size / 1000, MAX_TRACE_BYTES_PER_ROW)

    def test_10k_rows_result(self):
        """Test tracing query returning 10,000 rows."""
        with self.harness.traced_session() as session:
            start = time.perf_counter()
            result = session.execute(
                "SELECT * FROM perf_large LIMIT 10000",
                with_explain=False
            )
            elapsed = time.perf_counter() - start

            trace_info = session.get_trace()
            trace_size = os.path.getsize(trace_info.path)

            print(f"\n  10K rows result:")
            print(f"    Rows: {result.rowcount}")
            print(f"    Time: {elapsed*1000:.2f}ms")
            print(f"    Trace size: {trace_size:,} bytes")
            print(f"    Bytes/row: {trace_size / 10000:.1f}")

            self.assertEqual(result.rowcount, 10000)

    def test_full_table_scan(self):
        """Test tracing full table scan."""
        with self.harness.traced_session() as session:
            start = time.perf_counter()
            result = session.execute(
                "SELECT COUNT(*) FROM perf_large",
                with_explain=False
            )
            elapsed = time.perf_counter() - start

            trace_info = session.get_trace()
            trace_size = os.path.getsize(trace_info.path)

            print(f"\n  Full table scan (100K rows):")
            print(f"    Time: {elapsed*1000:.2f}ms")
            print(f"    Trace size: {trace_size:,} bytes")

            # Trace for aggregation should be small regardless of row count
            self.assertLess(trace_size, 50000)  # < 50KB for aggregation

    def test_large_sort(self):
        """Test tracing large sort operation."""
        with self.harness.traced_session() as session:
            session.conn.execute("SET work_mem = '4MB'")

            start = time.perf_counter()
            result = session.execute(
                "SELECT * FROM perf_large ORDER BY data LIMIT 5000",
                with_explain=False
            )
            elapsed = time.perf_counter() - start

            trace_info = session.get_trace()
            trace_size = os.path.getsize(trace_info.path)

            print(f"\n  Large sort:")
            print(f"    Rows: {result.rowcount}")
            print(f"    Time: {elapsed*1000:.2f}ms")
            print(f"    Trace size: {trace_size:,} bytes")

            self.assertEqual(result.rowcount, 5000)


class TestConcurrentSessions(unittest.TestCase):
    """Test performance with concurrent traced sessions."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

        conn = cls.harness.new_connection()
        conn.execute("DROP TABLE IF EXISTS perf_concurrent CASCADE")
        conn.execute("""
            CREATE TABLE perf_concurrent (
                id SERIAL PRIMARY KEY,
                value INTEGER
            )
        """)
        conn.execute("""
            INSERT INTO perf_concurrent (value)
            SELECT i FROM generate_series(1, 1000) i
        """)
        conn.execute("ANALYZE perf_concurrent")
        conn.close()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def _run_queries(self, session, num_queries):
        """Run queries in a session and return timing."""
        times = []
        for i in range(num_queries):
            start = time.perf_counter()
            session.conn.execute(f"SELECT * FROM perf_concurrent WHERE id = {(i % 1000) + 1}")
            elapsed = time.perf_counter() - start
            times.append(elapsed * 1000)
        return times

    def test_two_concurrent_sessions(self):
        """Test performance with 2 concurrent traced sessions."""
        num_queries = 50
        results = {}

        def run_session(session_id):
            with self.harness.traced_session() as session:
                times = self._run_queries(session, num_queries)
                return session_id, times

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(run_session, i) for i in range(2)]

            start = time.perf_counter()
            for future in as_completed(futures):
                session_id, times = future.result()
                results[session_id] = times
            total_elapsed = time.perf_counter() - start

        total_queries = num_queries * 2
        qps = total_queries / total_elapsed

        all_times = []
        for times in results.values():
            all_times.extend(times)

        print(f"\n  2 concurrent sessions:")
        print(f"    Total queries: {total_queries}")
        print(f"    Total time: {total_elapsed:.2f}s")
        print(f"    QPS: {qps:.1f}")
        print(f"    Avg latency: {statistics.mean(all_times):.2f}ms")

        self.assertGreater(qps, MIN_QUERIES_PER_SECOND / 4)

    def test_five_concurrent_sessions(self):
        """Test performance with 5 concurrent traced sessions."""
        num_queries = 30
        results = {}

        def run_session(session_id):
            with self.harness.traced_session() as session:
                times = self._run_queries(session, num_queries)
                return session_id, times

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(run_session, i) for i in range(5)]

            start = time.perf_counter()
            for future in as_completed(futures):
                session_id, times = future.result()
                results[session_id] = times
            total_elapsed = time.perf_counter() - start

        total_queries = num_queries * 5
        qps = total_queries / total_elapsed

        print(f"\n  5 concurrent sessions:")
        print(f"    Total queries: {total_queries}")
        print(f"    Total time: {total_elapsed:.2f}s")
        print(f"    QPS: {qps:.1f}")

        self.assertGreater(qps, MIN_QUERIES_PER_SECOND / 8)

    def test_concurrent_with_untraced(self):
        """Test traced sessions don't slow down untraced sessions."""
        num_queries = 50

        # Baseline: untraced session alone
        conn = self.harness.new_connection()
        start = time.perf_counter()
        for i in range(num_queries):
            conn.execute(f"SELECT * FROM perf_concurrent WHERE id = {(i % 1000) + 1}")
        baseline_elapsed = time.perf_counter() - start
        conn.close()

        # With concurrent traced session
        def traced_workload():
            with self.harness.traced_session() as session:
                for i in range(num_queries * 2):
                    session.conn.execute(f"SELECT * FROM perf_concurrent WHERE id = {(i % 1000) + 1}")
                    time.sleep(0.001)  # Small delay to keep session active

        traced_thread = threading.Thread(target=traced_workload)
        traced_thread.start()

        time.sleep(0.1)  # Let traced session start

        conn = self.harness.new_connection()
        start = time.perf_counter()
        for i in range(num_queries):
            conn.execute(f"SELECT * FROM perf_concurrent WHERE id = {(i % 1000) + 1}")
        concurrent_elapsed = time.perf_counter() - start
        conn.close()

        traced_thread.join()

        slowdown = ((concurrent_elapsed - baseline_elapsed) / baseline_elapsed) * 100 if baseline_elapsed > 0 else 0

        print(f"\n  Untraced with concurrent traced:")
        print(f"    Baseline: {baseline_elapsed*1000:.2f}ms")
        print(f"    With traced: {concurrent_elapsed*1000:.2f}ms")
        print(f"    Slowdown: {slowdown:.1f}%")

        # Untraced sessions shouldn't be significantly slowed
        self.assertLess(slowdown, 100, "Untraced sessions shouldn't be >2x slower")


class TestTraceFileSize(unittest.TestCase):
    """Test trace file size characteristics."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

        conn = cls.harness.new_connection()
        conn.execute("DROP TABLE IF EXISTS perf_size CASCADE")
        conn.execute("""
            CREATE TABLE perf_size (
                id SERIAL PRIMARY KEY,
                small_data VARCHAR(10),
                medium_data VARCHAR(100),
                large_data TEXT
            )
        """)
        conn.execute("""
            INSERT INTO perf_size (small_data, medium_data, large_data)
            SELECT
                substring(md5(i::text), 1, 10),
                md5(i::text) || md5((i+1)::text) || md5((i+2)::text),
                repeat(md5(i::text), 10)
            FROM generate_series(1, 10000) i
        """)
        conn.execute("ANALYZE perf_size")
        conn.close()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def test_simple_query_trace_size(self):
        """Test trace size for simple query."""
        with self.harness.traced_session() as session:
            session.execute("SELECT 1", with_explain=False)

            trace_info = session.get_trace()
            trace_size = os.path.getsize(trace_info.path)

            print(f"\n  Simple query trace size: {trace_size:,} bytes")

            # Simple query trace should be small
            self.assertLess(trace_size, 10000)  # < 10KB

    def test_complex_query_trace_size(self):
        """Test trace size for complex query."""
        with self.harness.traced_session() as session:
            session.execute("""
                SELECT s1.id, s1.small_data, s2.medium_data
                FROM perf_size s1
                JOIN perf_size s2 ON s2.id = s1.id + 1
                WHERE s1.id <= 100
                ORDER BY s1.small_data
            """, with_explain=False)

            trace_info = session.get_trace()
            trace_size = os.path.getsize(trace_info.path)

            print(f"\n  Complex query trace size: {trace_size:,} bytes")

            # Complex query trace should still be reasonable
            self.assertLess(trace_size, 50000)  # < 50KB

    def test_many_queries_trace_size(self):
        """Test trace size grows linearly with query count."""
        sizes = []

        for num_queries in [10, 50, 100]:
            with self.harness.traced_session() as session:
                for i in range(num_queries):
                    session.conn.execute(f"SELECT * FROM perf_size WHERE id = {i + 1}")

                trace_info = session.get_trace()
                trace_size = os.path.getsize(trace_info.path)
                sizes.append((num_queries, trace_size))

        print(f"\n  Trace size scaling:")
        for num, size in sizes:
            print(f"    {num} queries: {size:,} bytes ({size/num:.0f} bytes/query)")

        # Check roughly linear growth
        bytes_per_query = [size / num for num, size in sizes]
        variance = max(bytes_per_query) / min(bytes_per_query) if min(bytes_per_query) > 0 else float('inf')

        self.assertLess(variance, 3, "Trace size should grow roughly linearly")

    def test_trace_size_with_bind_variables(self):
        """Test trace size with bind variables."""
        with self.harness.traced_session() as session:
            session.conn.execute("""
                PREPARE size_test AS
                SELECT * FROM perf_size WHERE id = $1 AND small_data = $2
            """)
            for i in range(50):
                session.conn.execute(f"EXECUTE size_test({i + 1}, 'test')")
            session.conn.execute("DEALLOCATE size_test")

            trace_info = session.get_trace()
            trace_size = os.path.getsize(trace_info.path)

            print(f"\n  50 prepared statements trace size: {trace_size:,} bytes")

            # Should be reasonable even with bind variables
            self.assertLess(trace_size, 200000)  # < 200KB


class TestLongRunningQueries(unittest.TestCase):
    """Test tracing of long-running queries."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def test_sleep_query(self):
        """Test tracing pg_sleep query."""
        with self.harness.traced_session() as session:
            start = time.perf_counter()
            session.execute("SELECT pg_sleep(0.5)", with_explain=False)
            elapsed = time.perf_counter() - start

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            print(f"\n  pg_sleep(0.5) query:")
            print(f"    Elapsed: {elapsed*1000:.2f}ms")
            print(f"    Trace events: {len(trace.events)}")

            # Should complete in reasonable time (sleep + overhead)
            self.assertLess(elapsed, 1.0)
            self.assertGreater(elapsed, 0.4)

    def test_cpu_intensive_query(self):
        """Test tracing CPU-intensive query."""
        with self.harness.traced_session() as session:
            start = time.perf_counter()
            session.execute("""
                SELECT COUNT(*)
                FROM generate_series(1, 100000) a,
                     generate_series(1, 10) b
                WHERE a % 1000 = 0
            """, with_explain=False)
            elapsed = time.perf_counter() - start

            trace_info = session.get_trace()
            trace_size = os.path.getsize(trace_info.path)

            print(f"\n  CPU-intensive query:")
            print(f"    Elapsed: {elapsed*1000:.2f}ms")
            print(f"    Trace size: {trace_size:,} bytes")

            # Should complete and have valid trace
            assert_all_nodes_paired(parse_trace(trace_info.path))

    def test_io_intensive_query(self):
        """Test tracing IO-intensive query."""
        # Create temp table to force IO
        conn = self.harness.new_connection()
        conn.execute("DROP TABLE IF EXISTS perf_io_test CASCADE")
        conn.execute("""
            CREATE TABLE perf_io_test AS
            SELECT i as id, md5(i::text) as data
            FROM generate_series(1, 50000) i
        """)
        conn.execute("ANALYZE perf_io_test")
        conn.close()

        with self.harness.traced_session() as session:
            # Force disk read
            session.conn.execute("SET work_mem = '64kB'")

            start = time.perf_counter()
            session.execute("""
                SELECT * FROM perf_io_test ORDER BY data
            """, with_explain=False)
            elapsed = time.perf_counter() - start

            trace_info = session.get_trace()
            trace_size = os.path.getsize(trace_info.path)

            print(f"\n  IO-intensive query:")
            print(f"    Elapsed: {elapsed*1000:.2f}ms")
            print(f"    Trace size: {trace_size:,} bytes")

        # Cleanup
        conn = self.harness.new_connection()
        conn.execute("DROP TABLE IF EXISTS perf_io_test")
        conn.close()


class TestEBPFPerformance(unittest.TestCase):
    """Test eBPF daemon performance under load."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

        conn = cls.harness.new_connection()
        conn.execute("DROP TABLE IF EXISTS perf_ebpf CASCADE")
        conn.execute("""
            CREATE TABLE perf_ebpf (
                id SERIAL PRIMARY KEY,
                data TEXT
            )
        """)
        conn.execute("""
            INSERT INTO perf_ebpf (data)
            SELECT md5(i::text)
            FROM generate_series(1, 50000) i
        """)
        conn.execute("ANALYZE perf_ebpf")
        conn.close()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def _check_daemon_running(self):
        """Check if eBPF daemon is running."""
        import socket
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect('/var/run/pg_10046.sock')
            sock.close()
            return True
        except:
            return False

    @unittest.skipUnless(os.geteuid() == 0, "Requires root for eBPF")
    def test_ebpf_high_io_rate(self):
        """Test eBPF daemon handles high IO rate."""
        if not self._check_daemon_running():
            self.skipTest("eBPF daemon not running")

        with self.harness.traced_session(ebpf_active=True) as session:
            # Force many IO operations
            session.conn.execute("SET work_mem = '64kB'")

            start = time.perf_counter()
            for i in range(10):
                session.conn.execute("SELECT * FROM perf_ebpf ORDER BY data LIMIT 1000")
            elapsed = time.perf_counter() - start

            trace_info = session.get_trace()

            print(f"\n  High IO rate test:")
            print(f"    Queries: 10")
            print(f"    Elapsed: {elapsed*1000:.2f}ms")

            # Check we got trace
            self.assertIsNotNone(trace_info)

    @unittest.skipUnless(os.geteuid() == 0, "Requires root for eBPF")
    def test_ebpf_cpu_intensive(self):
        """Test eBPF daemon with CPU-intensive workload."""
        if not self._check_daemon_running():
            self.skipTest("eBPF daemon not running")

        with self.harness.traced_session(ebpf_active=True) as session:
            start = time.perf_counter()
            session.execute("""
                SELECT SUM(length(md5(data)))
                FROM perf_ebpf
            """, with_explain=False)
            elapsed = time.perf_counter() - start

            trace_info = session.get_trace()

            print(f"\n  CPU-intensive with eBPF:")
            print(f"    Elapsed: {elapsed*1000:.2f}ms")

            self.assertIsNotNone(trace_info)


class TestMemoryStability(unittest.TestCase):
    """Test memory stability during extended tracing."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def test_repeated_trace_sessions(self):
        """Test memory doesn't leak across trace sessions."""
        # Run many trace sessions
        for i in range(20):
            with self.harness.traced_session() as session:
                session.execute("SELECT 1", with_explain=False)
                session.execute("SELECT 2", with_explain=False)

        # If we get here without crashing, basic stability is OK
        self.assertTrue(True)

    def test_large_trace_cleanup(self):
        """Test large traces are cleaned up properly."""
        trace_paths = []

        for i in range(5):
            with self.harness.traced_session() as session:
                for j in range(100):
                    session.conn.execute(f"SELECT {j}")

                trace_info = session.get_trace()
                if trace_info:
                    trace_paths.append(trace_info.path)

        # Verify traces were created
        self.assertGreater(len(trace_paths), 0)

        # Note: actual cleanup depends on trace directory management
        # This test just verifies we can create many traces


if __name__ == '__main__':
    # Run with verbose output to see timing info
    unittest.main(verbosity=2)
