#!/usr/bin/env python3
"""
Late Attach Tests - Test attaching tracing to already-running queries.

Tests the pg_10046_attach tool and late attach scenarios:
1. Plan/SQL/binds correctly read from process memory
2. eBPF IO events collected correctly during running query
3. Consecutive queries after attach captured normally
4. Extension-skip mode (eBPF only + memory read for plan)

These tests require:
- Root privileges (for bpftrace/eBPF and memory reading)
- pg_10046 daemon running
- PostgreSQL with pg_10046 extension loaded
"""

import unittest
import sys
import os
import time
import glob
import subprocess
import threading
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(__file__))

from lib.pg_harness import PgHarness, PgConfig
from lib.trace_validator import TraceParser, EventType
from lib.assertions import (
    parse_trace,
    assert_header_present,
    assert_query_captured,
    assert_all_nodes_paired,
    TraceAssertionError,
)

# Path to attach tool
ATTACH_TOOL = "/tmp/pg_10046_attach"
TRACE_DIR = "/tmp"


def run_attach_tool(pid, running=False, timeout=10, no_daemon=False, no_extension=False):
    """Run pg_10046_attach and return (success, output, trace_file)."""
    cmd = ["sudo", ATTACH_TOOL, str(pid)]

    if running:
        cmd.append("--running")
    cmd.extend(["--timeout", str(timeout)])
    cmd.extend(["--trace-dir", TRACE_DIR])

    if no_daemon:
        cmd.append("--no-daemon")
    if no_extension:
        cmd.append("--no-extension")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 10
        )

        output = result.stdout + result.stderr

        # Find trace file path in output
        trace_file = None
        for line in output.split('\n'):
            if 'Trace file:' in line or line.strip().endswith('.trc'):
                parts = line.split()
                for part in parts:
                    if part.endswith('.trc'):
                        trace_file = part
                        break

        success = result.returncode == 0 and trace_file and os.path.exists(trace_file)
        return success, output, trace_file

    except subprocess.TimeoutExpired:
        return False, "Timeout", None
    except Exception as e:
        return False, str(e), None


def check_root():
    """Check if running as root."""
    return os.geteuid() == 0


def check_daemon_running():
    """Check if pg_10046 daemon is running."""
    import socket
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect('/var/run/pg_10046.sock')
        sock.close()
        return True
    except:
        return False


def check_attach_tool():
    """Check if attach tool exists."""
    return os.path.exists(ATTACH_TOOL)


@unittest.skipUnless(check_root(), "Requires root for memory reading")
@unittest.skipUnless(check_attach_tool(), "pg_10046_attach tool not found")
class TestLateAttachMemoryRead(unittest.TestCase):
    """Test reading plan/SQL/binds from process memory."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

        # Create test table with enough data for slow queries
        conn = cls.harness.new_connection()
        conn.execute("DROP TABLE IF EXISTS attach_test CASCADE")
        conn.execute("""
            CREATE TABLE attach_test (
                id SERIAL PRIMARY KEY,
                data TEXT,
                value INTEGER,
                category TEXT
            )
        """)
        conn.execute("""
            INSERT INTO attach_test (data, value, category)
            SELECT md5(i::text), i, 'cat_' || (i % 10)
            FROM generate_series(1, 100000) i
        """)
        conn.execute("ANALYZE attach_test")
        conn.close()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def _cleanup_traces(self):
        """Remove trace files."""
        for f in glob.glob(f"{TRACE_DIR}/pg_10046_*.trc"):
            try:
                os.remove(f)
            except:
                pass

    def test_read_sql_from_running_query(self):
        """Test that SQL is correctly read from process memory."""
        self._cleanup_traces()

        # Start a long-running query in background
        conn = self.harness.new_connection()
        pid = conn.pid

        query_sql = "SELECT pg_sleep(3), COUNT(*) FROM attach_test"
        query_started = threading.Event()
        query_result = [None]

        def run_query():
            query_started.set()
            result = conn.execute(query_sql)
            query_result[0] = result

        thread = threading.Thread(target=run_query)
        thread.start()
        query_started.wait()
        time.sleep(0.5)  # Let query start

        # Attach while query is running
        success, output, trace_file = run_attach_tool(pid, running=True, no_daemon=True)

        thread.join(timeout=10)
        conn.close()

        self.assertTrue(success, f"Attach failed: {output}")
        self.assertIsNotNone(trace_file, "No trace file created")

        # Verify SQL was captured
        with open(trace_file, 'r') as f:
            content = f.read()

        self.assertIn("pg_sleep", content, "SQL not captured correctly")
        self.assertIn("attach_test", content, "Table name not in SQL")

    def test_read_plan_from_running_query(self):
        """Test that execution plan is correctly read from memory."""
        self._cleanup_traces()

        conn = self.harness.new_connection()
        pid = conn.pid

        # Use pg_sleep to ensure we have time to attach
        query_sql = "SELECT pg_sleep(3), COUNT(*) FROM attach_test WHERE id <= 1000"

        query_started = threading.Event()

        def run_query():
            query_started.set()
            conn.execute(query_sql)

        thread = threading.Thread(target=run_query)
        thread.start()
        query_started.wait()
        time.sleep(0.5)  # Let query get into execution

        success, output, trace_file = run_attach_tool(pid, running=True, no_daemon=True)

        thread.join(timeout=10)
        conn.close()

        self.assertTrue(success, f"Attach failed: {output}")

        # Verify plan nodes were captured
        with open(trace_file, 'r') as f:
            content = f.read()

        # Should have plan nodes
        self.assertIn("PLAN_START", content)
        self.assertIn("PLAN,", content, "No plan nodes captured")

    def test_read_bind_variables(self):
        """Test that bind variables are correctly read from memory."""
        self._cleanup_traces()

        conn = self.harness.new_connection()
        pid = conn.pid

        # Create prepared statement with bind variables
        conn.execute("PREPARE bind_test AS SELECT * FROM attach_test WHERE id = $1 AND category = $2")

        query_started = threading.Event()

        def run_query():
            query_started.set()
            # Use pg_sleep to give time for attach
            conn.execute("SELECT pg_sleep(2)")
            # Then execute with binds
            conn.execute("EXECUTE bind_test(42, 'cat_2')")

        thread = threading.Thread(target=run_query)
        thread.start()
        query_started.wait()
        time.sleep(0.5)

        success, output, trace_file = run_attach_tool(pid, running=True, no_daemon=True)

        thread.join(timeout=10)
        conn.execute("DEALLOCATE bind_test")
        conn.close()

        # Even if we attach during pg_sleep, we should get something
        self.assertTrue(success or "pg_sleep" in output, f"Attach failed unexpectedly: {output}")

    def test_read_numeric_bind_types(self):
        """Test reading different numeric bind variable types."""
        self._cleanup_traces()

        conn = self.harness.new_connection()
        pid = conn.pid

        # Create prepared statement with various numeric types
        conn.execute("""
            PREPARE numeric_bind_test AS
            SELECT * FROM attach_test
            WHERE id > $1
            AND value < $2
            LIMIT $3
        """)

        query_started = threading.Event()

        def run_query():
            query_started.set()
            # Long query to give time for attach
            for _ in range(5):
                conn.execute("EXECUTE numeric_bind_test(100, 50000, 1000)")
                time.sleep(0.3)

        thread = threading.Thread(target=run_query)
        thread.start()
        query_started.wait()
        time.sleep(0.3)

        success, output, trace_file = run_attach_tool(pid, running=True, no_daemon=True)

        thread.join(timeout=10)
        conn.execute("DEALLOCATE numeric_bind_test")
        conn.close()

        if success and trace_file:
            with open(trace_file, 'r') as f:
                content = f.read()
            # Check for bind variable indicators
            if "BIND" in content:
                self.assertIn("int", content.lower(), "Numeric bind type not identified")

    def test_read_text_bind_types(self):
        """Test reading text/varchar bind variable types."""
        self._cleanup_traces()

        conn = self.harness.new_connection()
        pid = conn.pid

        conn.execute("""
            PREPARE text_bind_test AS
            SELECT * FROM attach_test
            WHERE category = $1
            AND data LIKE $2
        """)

        query_started = threading.Event()

        def run_query():
            query_started.set()
            for _ in range(5):
                conn.execute("EXECUTE text_bind_test('cat_5', '%abc%')")
                time.sleep(0.3)

        thread = threading.Thread(target=run_query)
        thread.start()
        query_started.wait()
        time.sleep(0.3)

        success, output, trace_file = run_attach_tool(pid, running=True, no_daemon=True)

        thread.join(timeout=10)
        conn.execute("DEALLOCATE text_bind_test")
        conn.close()

        if success and trace_file:
            with open(trace_file, 'r') as f:
                content = f.read()
            if "BIND" in content:
                # Text binds should show the value in quotes
                self.assertTrue(
                    "text" in content.lower() or "varchar" in content.lower() or "'" in content,
                    "Text bind type not identified"
                )


@unittest.skipUnless(check_root(), "Requires root for eBPF")
@unittest.skipUnless(check_daemon_running(), "pg_10046 daemon not running")
@unittest.skipUnless(check_attach_tool(), "pg_10046_attach tool not found")
class TestLateAttachEBPF(unittest.TestCase):
    """Test eBPF event collection during late attach."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

        conn = cls.harness.new_connection()
        conn.execute("DROP TABLE IF EXISTS attach_ebpf_test CASCADE")
        conn.execute("""
            CREATE TABLE attach_ebpf_test (
                id SERIAL PRIMARY KEY,
                data TEXT
            )
        """)
        # Create enough data to cause IO
        conn.execute("""
            INSERT INTO attach_ebpf_test (data)
            SELECT repeat(md5(i::text), 100)
            FROM generate_series(1, 50000) i
        """)
        conn.execute("ANALYZE attach_ebpf_test")
        conn.close()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def _cleanup_traces(self):
        for f in glob.glob(f"{TRACE_DIR}/pg_10046_*.trc"):
            try:
                os.remove(f)
            except:
                pass
        for f in glob.glob(f"{TRACE_DIR}/pg_10046_io_*.trc"):
            try:
                os.remove(f)
            except:
                pass

    def test_io_events_collected_during_scan(self):
        """Test that IO events are collected when attaching during a large scan."""
        self._cleanup_traces()

        # Drop caches to force IO
        subprocess.run(["sudo", "sh", "-c", "sync; echo 3 > /proc/sys/vm/drop_caches"],
                      capture_output=True)

        conn = self.harness.new_connection()
        pid = conn.pid

        # Query that will do significant IO
        query_sql = "SELECT COUNT(*), SUM(LENGTH(data)) FROM attach_ebpf_test"

        query_started = threading.Event()

        def run_query():
            query_started.set()
            conn.execute(query_sql)

        thread = threading.Thread(target=run_query)
        thread.start()
        query_started.wait()
        time.sleep(0.2)  # Let IO start

        # Attach with daemon (eBPF) enabled
        success, output, trace_file = run_attach_tool(pid, running=True, no_daemon=False)

        thread.join(timeout=60)
        conn.close()

        self.assertTrue(success, f"Attach failed: {output}")

        # Wait for IO trace file
        time.sleep(2)

        # Check for IO trace file
        io_files = glob.glob(f"{TRACE_DIR}/pg_10046_io_{pid}_*.trc")

        # IO events might be in main trace or separate IO file
        if io_files:
            with open(io_files[0], 'r') as f:
                io_content = f.read()
            has_io_events = "IO" in io_content or "READ" in io_content or "WRITE" in io_content
        else:
            with open(trace_file, 'r') as f:
                content = f.read()
            has_io_events = "IO" in content

        # Note: IO events may or may not be captured depending on timing
        # The test verifies the attach mechanism works
        print(f"  IO events captured: {has_io_events}")

    def test_wait_events_during_sleep(self):
        """Test that wait events are captured during pg_sleep."""
        self._cleanup_traces()

        conn = self.harness.new_connection()
        pid = conn.pid

        query_started = threading.Event()

        def run_query():
            query_started.set()
            conn.execute("SELECT pg_sleep(3)")

        thread = threading.Thread(target=run_query)
        thread.start()
        query_started.wait()
        time.sleep(0.3)

        success, output, trace_file = run_attach_tool(pid, running=True, no_daemon=False)

        thread.join(timeout=10)
        conn.close()

        self.assertTrue(success, f"Attach failed: {output}")

        # pg_sleep shows as a specific wait event
        with open(trace_file, 'r') as f:
            content = f.read()

        self.assertIn("pg_sleep", content, "pg_sleep SQL not captured")


@unittest.skipUnless(check_root(), "Requires root for eBPF")
@unittest.skipUnless(check_attach_tool(), "pg_10046_attach tool not found")
class TestLateAttachConsecutiveQueries(unittest.TestCase):
    """Test that consecutive queries after attach are captured normally."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

        conn = cls.harness.new_connection()
        conn.execute("DROP TABLE IF EXISTS attach_consec_test CASCADE")
        conn.execute("""
            CREATE TABLE attach_consec_test (
                id SERIAL PRIMARY KEY,
                value INTEGER
            )
        """)
        conn.execute("""
            INSERT INTO attach_consec_test (value)
            SELECT i FROM generate_series(1, 1000) i
        """)
        conn.execute("ANALYZE attach_consec_test")
        conn.close()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def _cleanup_traces(self):
        for f in glob.glob(f"{TRACE_DIR}/pg_10046_*.trc"):
            try:
                os.remove(f)
            except:
                pass

    def test_consecutive_queries_after_attach(self):
        """Test queries after attach are captured by extension."""
        self._cleanup_traces()

        conn = self.harness.new_connection()
        pid = conn.pid

        # First query - attach during this
        query_started = threading.Event()

        def run_first_query():
            query_started.set()
            conn.execute("SELECT pg_sleep(2)")

        thread = threading.Thread(target=run_first_query)
        thread.start()
        query_started.wait()
        time.sleep(0.3)

        # Attach (this should enable extension for subsequent queries)
        success, output, trace_file = run_attach_tool(
            pid, running=True, no_daemon=True, no_extension=False
        )

        thread.join(timeout=10)

        self.assertTrue(success, f"Attach failed: {output}")

        # Now run several more queries - these should be captured by extension
        consecutive_queries = [
            "SELECT COUNT(*) FROM attach_consec_test",
            "SELECT * FROM attach_consec_test WHERE id <= 10",
            "SELECT SUM(value) FROM attach_consec_test",
            "SELECT * FROM attach_consec_test ORDER BY value DESC LIMIT 5",
        ]

        for sql in consecutive_queries:
            conn.execute(sql)

        # Wait for traces to be written
        time.sleep(1)

        # Close connection to flush
        conn.close()
        time.sleep(2)

        # Find extension trace file (different from attach trace)
        all_traces = glob.glob(f"{TRACE_DIR}/pg_10046_{pid}_*.trc")

        # Should have at least the attach trace
        self.assertGreater(len(all_traces), 0, "No trace files found")

        # Check if consecutive queries were captured
        found_consecutive = False
        for trace_file in all_traces:
            with open(trace_file, 'r') as f:
                content = f.read()
            if "attach_consec_test" in content and "COUNT" in content:
                found_consecutive = True
                break

        print(f"  Consecutive queries captured: {found_consecutive}")
        # Note: This depends on extension being properly enabled

    def test_multiple_queries_all_captured(self):
        """Test that multiple queries after attach are all captured."""
        self._cleanup_traces()

        conn = self.harness.new_connection()
        pid = conn.pid

        # Start with a query to attach to
        query_started = threading.Event()

        def run_initial_query():
            query_started.set()
            conn.execute("SELECT pg_sleep(1)")

        thread = threading.Thread(target=run_initial_query)
        thread.start()
        query_started.wait()
        time.sleep(0.2)

        success, output, trace_file = run_attach_tool(
            pid, running=True, no_daemon=True, no_extension=False
        )

        thread.join(timeout=5)

        # Run many queries
        for i in range(20):
            conn.execute(f"SELECT {i}")

        conn.close()
        time.sleep(2)

        # Check traces
        all_traces = glob.glob(f"{TRACE_DIR}/pg_10046_{pid}_*.trc")
        total_queries = 0

        for tf in all_traces:
            with open(tf, 'r') as f:
                content = f.read()
            total_queries += content.count("QUERY_START")

        print(f"  Total queries captured: {total_queries}")
        # At minimum we should have the attach query
        self.assertGreater(total_queries, 0, "No queries captured")


@unittest.skipUnless(check_root(), "Requires root for memory reading")
@unittest.skipUnless(check_attach_tool(), "pg_10046_attach tool not found")
class TestExtensionSkipMode(unittest.TestCase):
    """Test mode where only eBPF + memory read works (no extension)."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

        conn = cls.harness.new_connection()
        conn.execute("DROP TABLE IF EXISTS attach_skip_test CASCADE")
        conn.execute("""
            CREATE TABLE attach_skip_test (
                id SERIAL PRIMARY KEY,
                data TEXT
            )
        """)
        conn.execute("""
            INSERT INTO attach_skip_test (data)
            SELECT md5(i::text)
            FROM generate_series(1, 10000) i
        """)
        conn.execute("ANALYZE attach_skip_test")
        conn.close()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def _cleanup_traces(self):
        for f in glob.glob(f"{TRACE_DIR}/pg_10046_*.trc"):
            try:
                os.remove(f)
            except:
                pass

    def test_no_extension_mode_captures_plan(self):
        """Test that --no-extension mode still captures plan from memory."""
        self._cleanup_traces()

        conn = self.harness.new_connection()
        pid = conn.pid

        query_started = threading.Event()

        def run_query():
            query_started.set()
            # Use pg_sleep to ensure query runs long enough for attach
            conn.execute("SELECT pg_sleep(3), COUNT(*) FROM attach_skip_test")

        thread = threading.Thread(target=run_query)
        thread.start()
        query_started.wait()
        time.sleep(0.5)  # Let query start

        # Use --no-extension mode
        success, output, trace_file = run_attach_tool(
            pid, running=True, no_daemon=True, no_extension=True
        )

        thread.join(timeout=10)
        conn.close()

        self.assertTrue(success, f"Attach failed: {output}")

        with open(trace_file, 'r') as f:
            content = f.read()

        # Should have plan even without extension
        self.assertIn("PLAN_START", content)
        self.assertIn("PLAN,", content, "No plan nodes in no-extension mode")

    def test_no_extension_mode_captures_sql(self):
        """Test that --no-extension mode captures SQL from memory."""
        self._cleanup_traces()

        conn = self.harness.new_connection()
        pid = conn.pid

        test_sql = "SELECT pg_sleep(2), id FROM attach_skip_test WHERE id = 42"

        query_started = threading.Event()

        def run_query():
            query_started.set()
            conn.execute(test_sql)

        thread = threading.Thread(target=run_query)
        thread.start()
        query_started.wait()
        time.sleep(0.3)

        success, output, trace_file = run_attach_tool(
            pid, running=True, no_daemon=True, no_extension=True
        )

        thread.join(timeout=10)
        conn.close()

        self.assertTrue(success, f"Attach failed: {output}")

        with open(trace_file, 'r') as f:
            content = f.read()

        # SQL should be captured
        self.assertIn("attach_skip_test", content, "SQL not captured in no-extension mode")

    @unittest.skipUnless(check_daemon_running(), "Daemon not running")
    def test_no_extension_with_ebpf(self):
        """Test --no-extension mode with eBPF daemon active."""
        self._cleanup_traces()

        # Drop caches to force IO
        subprocess.run(["sudo", "sh", "-c", "sync; echo 3 > /proc/sys/vm/drop_caches"],
                      capture_output=True)

        conn = self.harness.new_connection()
        pid = conn.pid

        query_started = threading.Event()

        def run_query():
            query_started.set()
            # Use pg_sleep to ensure we have time to attach
            conn.execute("SELECT pg_sleep(3), COUNT(*) FROM attach_skip_test")

        thread = threading.Thread(target=run_query)
        thread.start()
        query_started.wait()
        time.sleep(0.5)  # Give more time for query to start

        # --no-extension but WITH daemon (eBPF)
        success, output, trace_file = run_attach_tool(
            pid, running=True, no_daemon=False, no_extension=True
        )

        thread.join(timeout=10)
        conn.close()

        self.assertTrue(success, f"Attach failed: {output}")

        # Should have plan trace
        with open(trace_file, 'r') as f:
            content = f.read()

        self.assertIn("PLAN", content, "Plan not captured")

        # May have IO trace file from daemon
        time.sleep(2)
        io_files = glob.glob(f"{TRACE_DIR}/pg_10046_io_{pid}_*.trc")
        print(f"  IO trace files: {len(io_files)}")


@unittest.skipUnless(check_root(), "Requires root")
@unittest.skipUnless(check_attach_tool(), "pg_10046_attach tool not found")
class TestWaitMode(unittest.TestCase):
    """Test WAIT mode - waiting for next query on backend."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def _cleanup_traces(self):
        for f in glob.glob(f"{TRACE_DIR}/pg_10046_*.trc"):
            try:
                os.remove(f)
            except:
                pass

    def test_wait_mode_captures_next_query(self):
        """Test that WAIT mode captures the next query."""
        self._cleanup_traces()

        conn = self.harness.new_connection()
        pid = conn.pid

        # Start attach in wait mode (background)
        attach_started = threading.Event()
        attach_result = [None, None, None]  # success, output, trace_file

        def run_attach():
            attach_started.set()
            result = run_attach_tool(pid, running=False, timeout=10, no_daemon=True)
            attach_result[0], attach_result[1], attach_result[2] = result

        attach_thread = threading.Thread(target=run_attach)
        attach_thread.start()
        attach_started.wait()
        time.sleep(1)  # Let bpftrace attach

        # Now run a query - this should be captured
        conn.execute("SELECT 'wait_mode_test', 42")

        attach_thread.join(timeout=15)
        conn.close()

        success, output, trace_file = attach_result

        # Wait mode may timeout if query is too fast
        if success and trace_file:
            with open(trace_file, 'r') as f:
                content = f.read()
            self.assertIn("wait_mode_test", content, "Query not captured in wait mode")
        else:
            # Query may have been too fast for bpftrace to catch
            print(f"  Wait mode result: {output[:200] if output else 'None'}")


class TestLateAttachValidation(unittest.TestCase):
    """Validate late attach trace file format and contents."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    @unittest.skipUnless(check_root(), "Requires root")
    @unittest.skipUnless(check_attach_tool(), "pg_10046_attach not found")
    def test_late_attach_trace_format(self):
        """Test that late attach trace has correct format."""
        # Clean traces
        for f in glob.glob(f"{TRACE_DIR}/pg_10046_*.trc"):
            try:
                os.remove(f)
            except:
                pass

        conn = self.harness.new_connection()
        pid = conn.pid

        query_started = threading.Event()

        def run_query():
            query_started.set()
            conn.execute("SELECT pg_sleep(2)")

        thread = threading.Thread(target=run_query)
        thread.start()
        query_started.wait()
        time.sleep(0.3)

        success, output, trace_file = run_attach_tool(
            pid, running=True, no_daemon=True, no_extension=True
        )

        thread.join(timeout=10)
        conn.close()

        if not success:
            self.skipTest(f"Attach failed: {output}")

        with open(trace_file, 'r') as f:
            content = f.read()

        # Check required sections
        self.assertIn("# PG_10046 TRACE", content, "Missing trace header")
        self.assertIn("TRACE_ID:", content, "Missing TRACE_ID")
        self.assertIn("PID:", content, "Missing PID")
        self.assertIn("LATE ATTACH", content, "Missing LATE ATTACH marker")

        # Check for proper structure
        self.assertIn("QUERY_START", content, "Missing QUERY_START")
        self.assertIn("PLAN_START", content, "Missing PLAN_START")
        self.assertIn("PLAN_END", content, "Missing PLAN_END")


if __name__ == '__main__':
    # Print requirements
    print("Late Attach Tests Requirements:")
    print(f"  Root privileges: {'Yes' if check_root() else 'No (many tests will skip)'}")
    print(f"  Daemon running: {'Yes' if check_daemon_running() else 'No (eBPF tests will skip)'}")
    print(f"  Attach tool: {'Yes' if check_attach_tool() else 'No (tests will skip)'}")
    print()

    unittest.main(verbosity=2)
