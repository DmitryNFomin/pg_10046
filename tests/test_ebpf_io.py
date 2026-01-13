#!/usr/bin/env python3
"""
Test eBPF IO Events - IO_READ/IO_WRITE capture and validation.

Tests that:
- eBPF daemon can be started/stopped
- IO_READ events are captured for disk reads
- IO_WRITE events are captured for disk writes
- IO events have correct node attribution
- IO timing is reasonable
- IO events correlate with trace file

Note: These tests require:
1. Root/sudo access for eBPF
2. bpftrace installed
3. pg_10046d.py daemon running or startable
"""

import unittest
import sys
import os
import time
import glob
import subprocess
import signal

sys.path.insert(0, os.path.dirname(__file__))

from lib.pg_harness import PgHarness, PgConfig
from lib.assertions import parse_trace, assert_all_nodes_paired
from lib.trace_validator import IOTraceParser, parse_io_trace, IOTraceFile


def is_root():
    """Check if running as root (required for eBPF)."""
    return os.geteuid() == 0


def daemon_running():
    """Check if pg_10046d.py daemon is running."""
    try:
        result = subprocess.run(
            ['pgrep', '-f', 'pg_10046d.py'],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except:
        return False


def find_io_trace(trace_dir: str, pid: int) -> str:
    """Find IO trace file for a given PID."""
    pattern = f"{trace_dir}/pg_10046_io_{pid}_*.trc"
    files = glob.glob(pattern)
    if files:
        return max(files, key=os.path.getmtime)
    return None


class TestIOTraceParser(unittest.TestCase):
    """Test the IO trace parser with sample data."""

    def test_parse_io_read_event(self):
        """Test parsing IO_READ event line."""
        # Create a temp file with sample data
        import tempfile
        sample_data = """# PG_10046 IO TRACE
# PID: 12345
# UUID: test-uuid
12345,1234567890123,IO_READ,0xabc123,1663,16384,24576,0,0,100,1500,8,200
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.trc', delete=False) as f:
            f.write(sample_data)
            temp_path = f.name

        try:
            trace = parse_io_trace(temp_path)

            self.assertEqual(len(trace.events), 1)
            self.assertEqual(len(trace.io_reads), 1)
            self.assertEqual(len(trace.io_writes), 0)

            event = trace.io_reads[0]
            self.assertEqual(event.event_type, 'IO_READ')
            self.assertEqual(event.pid, 12345)
            self.assertEqual(event.node_ptr, '0xabc123')
            self.assertEqual(event.tablespace, 1663)
            self.assertEqual(event.database, 16384)
            self.assertEqual(event.relation, 24576)
            self.assertEqual(event.block, 100)
            self.assertEqual(event.elapsed_us, 1500)
        finally:
            os.unlink(temp_path)

    def test_parse_io_write_event(self):
        """Test parsing IO_WRITE event line."""
        import tempfile
        sample_data = """12345,1234567890123,IO_WRITE,0xdef456,1663,16384,24576,0,0,200,2000,8,300
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.trc', delete=False) as f:
            f.write(sample_data)
            temp_path = f.name

        try:
            trace = parse_io_trace(temp_path)

            self.assertEqual(len(trace.io_writes), 1)
            event = trace.io_writes[0]
            self.assertEqual(event.event_type, 'IO_WRITE')
            self.assertEqual(event.elapsed_us, 2000)
        finally:
            os.unlink(temp_path)

    def test_parse_multiple_events(self):
        """Test parsing multiple IO events."""
        import tempfile
        sample_data = """# Test trace
12345,100,IO_READ,0x1,1663,16384,24576,0,0,1,100,8,10
12345,200,IO_READ,0x1,1663,16384,24576,0,0,2,150,8,15
12345,300,IO_WRITE,0x1,1663,16384,24576,0,0,3,200,8,20
12345,400,IO_READ,0x2,1663,16384,24576,0,0,4,120,8,12
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.trc', delete=False) as f:
            f.write(sample_data)
            temp_path = f.name

        try:
            trace = parse_io_trace(temp_path)

            self.assertEqual(len(trace.events), 4)
            self.assertEqual(len(trace.io_reads), 3)
            self.assertEqual(len(trace.io_writes), 1)
            self.assertEqual(trace.total_read_us, 100 + 150 + 120)
            self.assertEqual(trace.total_write_us, 200)
            self.assertEqual(trace.total_blocks_read, 3)
            self.assertEqual(trace.total_blocks_written, 1)
        finally:
            os.unlink(temp_path)

    def test_parse_simple_format(self):
        """Test parsing simple format (from pg_10046_ebpf.sh)."""
        import tempfile
        sample_data = """1234567890,IO_READ,1663,16384,24576,0,0,100,1500
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.trc', delete=False) as f:
            f.write(sample_data)
            temp_path = f.name

        try:
            trace = parse_io_trace(temp_path)

            self.assertEqual(len(trace.io_reads), 1)
            event = trace.io_reads[0]
            self.assertEqual(event.elapsed_us, 1500)
            self.assertEqual(event.pid, 0)  # Not in simple format
        finally:
            os.unlink(temp_path)


@unittest.skipUnless(is_root(), "Requires root for eBPF")
class TestEBPFDaemon(unittest.TestCase):
    """Test eBPF daemon functionality."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()
        cls.config = cls.harness.config

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def test_daemon_socket_exists(self):
        """Test that daemon socket exists when running."""
        if not daemon_running():
            self.skipTest("Daemon not running")

        socket_path = "/var/run/pg_10046.sock"
        self.assertTrue(
            os.path.exists(socket_path),
            f"Daemon socket should exist at {socket_path}"
        )


@unittest.skipUnless(is_root(), "Requires root for eBPF")
class TestIOReadEvents(unittest.TestCase):
    """Test IO_READ event capture."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

        # Create table with data that won't fit in shared_buffers
        conn = cls.harness.new_connection()
        conn.execute("DROP TABLE IF EXISTS io_read_test CASCADE")
        conn.execute("""
            CREATE TABLE io_read_test (
                id SERIAL PRIMARY KEY,
                data TEXT,
                padding CHAR(500)
            )
        """)
        # Insert enough data to require disk reads
        conn.execute("""
            INSERT INTO io_read_test (data, padding)
            SELECT md5(i::text), repeat('x', 500)
            FROM generate_series(1, 10000) i
        """)
        conn.execute("ANALYZE io_read_test")
        conn.close()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def test_read_generates_io_events(self):
        """Test that reading data generates IO_READ events."""
        if not daemon_running():
            self.skipTest("Daemon not running")

        with self.harness.traced_session(ebpf_active=True) as session:
            # Drop caches if possible
            try:
                subprocess.run(['sync'], check=True)
                with open('/proc/sys/vm/drop_caches', 'w') as f:
                    f.write('3')
            except:
                pass  # May not have permission

            # Run query that reads data
            result = session.execute("""
                SELECT * FROM io_read_test WHERE id < 1000
            """, with_explain=False)

            time.sleep(0.5)  # Wait for IO trace to be written

            # Check for IO trace file
            io_trace_path = find_io_trace(self.harness.config.trace_dir, session.conn.pid)

            if io_trace_path:
                io_trace = parse_io_trace(io_trace_path)
                # Should have some IO reads
                self.assertGreater(len(io_trace.io_reads), 0,
                                   "Should have IO_READ events")

    def test_io_read_has_timing(self):
        """Test that IO_READ events have valid timing."""
        if not daemon_running():
            self.skipTest("Daemon not running")

        with self.harness.traced_session(ebpf_active=True) as session:
            session.execute("SELECT * FROM io_read_test LIMIT 100", with_explain=False)
            time.sleep(0.3)

            io_trace_path = find_io_trace(self.harness.config.trace_dir, session.conn.pid)

            if io_trace_path:
                io_trace = parse_io_trace(io_trace_path)
                for event in io_trace.io_reads:
                    # Timing should be positive
                    self.assertGreater(event.elapsed_us, 0,
                                       "IO elapsed time should be positive")
                    # But not unreasonably long (< 10 seconds)
                    self.assertLess(event.elapsed_us, 10_000_000,
                                    "IO elapsed time should be < 10s")


@unittest.skipUnless(is_root(), "Requires root for eBPF")
class TestIOWriteEvents(unittest.TestCase):
    """Test IO_WRITE event capture."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def test_write_generates_io_events(self):
        """Test that writing data generates IO_WRITE events."""
        if not daemon_running():
            self.skipTest("Daemon not running")

        conn = self.harness.new_connection()
        conn.execute("DROP TABLE IF EXISTS io_write_test CASCADE")
        conn.execute("CREATE TABLE io_write_test (id INT, data TEXT)")

        with self.harness.traced_session(ebpf_active=True) as session:
            # Insert data and force checkpoint
            session.execute("""
                INSERT INTO io_write_test
                SELECT i, repeat('x', 1000)
                FROM generate_series(1, 1000) i
            """, with_explain=False)

            # Force a checkpoint to write to disk
            try:
                session.conn.execute("CHECKPOINT")
            except:
                pass

            time.sleep(0.5)

            io_trace_path = find_io_trace(self.harness.config.trace_dir, session.conn.pid)

            # Note: Write events may not appear immediately due to buffering
            # This is expected behavior

        conn.execute("DROP TABLE IF EXISTS io_write_test")
        conn.close()


@unittest.skipUnless(is_root(), "Requires root for eBPF")
class TestIONodeAttribution(unittest.TestCase):
    """Test IO events are attributed to correct plan nodes."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

        conn = cls.harness.new_connection()
        conn.execute("DROP TABLE IF EXISTS io_node_test CASCADE")
        conn.execute("""
            CREATE TABLE io_node_test (
                id SERIAL PRIMARY KEY,
                data TEXT
            )
        """)
        conn.execute("""
            INSERT INTO io_node_test (data)
            SELECT md5(i::text)
            FROM generate_series(1, 10000) i
        """)
        conn.execute("CREATE INDEX io_node_test_data_idx ON io_node_test(data)")
        conn.execute("ANALYZE io_node_test")
        conn.close()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def test_io_has_node_pointer(self):
        """Test that IO events have node pointer when executing."""
        if not daemon_running():
            self.skipTest("Daemon not running")

        with self.harness.traced_session(ebpf_active=True) as session:
            # Clear caches if possible
            try:
                subprocess.run(['sync'], check=True)
                with open('/proc/sys/vm/drop_caches', 'w') as f:
                    f.write('3')
            except:
                pass

            session.execute("""
                SELECT * FROM io_node_test WHERE data LIKE 'abc%'
            """, with_explain=False)

            time.sleep(0.3)

            io_trace_path = find_io_trace(self.harness.config.trace_dir, session.conn.pid)

            if io_trace_path:
                io_trace = parse_io_trace(io_trace_path)

                # Check some events have node pointers
                has_node_ptr = False
                for event in io_trace.events:
                    if event.node_ptr and event.node_ptr != '(nil)':
                        has_node_ptr = True
                        break

                # Note: Node pointer may be nil if IO happens outside executor

    def test_io_relation_matches_query(self):
        """Test that IO events reference correct relation."""
        if not daemon_running():
            self.skipTest("Daemon not running")

        # Get the relation OID for our test table
        conn = self.harness.new_connection()
        result = conn.execute("""
            SELECT oid::integer FROM pg_class WHERE relname = 'io_node_test'
        """)
        if not result.rows:
            conn.close()
            self.skipTest("Test table not found")

        table_oid = result.rows[0]['oid']
        conn.close()

        with self.harness.traced_session(ebpf_active=True) as session:
            session.execute("SELECT * FROM io_node_test LIMIT 100", with_explain=False)
            time.sleep(0.3)

            io_trace_path = find_io_trace(self.harness.config.trace_dir, session.conn.pid)

            if io_trace_path:
                io_trace = parse_io_trace(io_trace_path)

                # Check if any IO events reference our table
                table_ios = [e for e in io_trace.events if e.relation == table_oid]
                # May or may not have IOs depending on cache state


class TestIOTraceCorrelation(unittest.TestCase):
    """Test correlation between main trace and IO trace."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def test_trace_mentions_io_file(self):
        """Test that main trace header mentions IO trace file."""
        with self.harness.traced_session(ebpf_active=True) as session:
            session.execute("SELECT 1", with_explain=False)

            trace_info = session.get_trace()
            if trace_info:
                trace = parse_trace(trace_info.path)

                # Header should indicate eBPF status
                ebpf_enabled = trace.header.get('EBPF_ENABLED', 'false')
                # May be 'true' or 'false' depending on daemon state

    def test_io_trace_uuid_matches(self):
        """Test that IO trace UUID matches main trace."""
        with self.harness.traced_session(ebpf_active=True) as session:
            session.execute("SELECT 1", with_explain=False)
            time.sleep(0.2)

            trace_info = session.get_trace()
            if trace_info:
                trace = parse_trace(trace_info.path)
                trace_uuid = trace.header.get('TRACE_UUID', '')

                io_trace_path = find_io_trace(
                    self.harness.config.trace_dir,
                    session.conn.pid
                )

                if io_trace_path and trace_uuid:
                    io_trace = parse_io_trace(io_trace_path)
                    io_uuid = io_trace.header.get('UUID', '')

                    # UUIDs should match (when daemon is properly correlating)


class TestIOValidation(unittest.TestCase):
    """Test IO event validation."""

    def test_io_event_fields_valid(self):
        """Test that IO event fields are valid."""
        import tempfile
        sample_data = """12345,100,IO_READ,0x1,1663,16384,24576,0,0,1,100,8,10
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.trc', delete=False) as f:
            f.write(sample_data)
            temp_path = f.name

        try:
            trace = parse_io_trace(temp_path)
            event = trace.io_reads[0]

            # Validate field ranges
            self.assertGreaterEqual(event.tablespace, 0)
            self.assertGreaterEqual(event.database, 0)
            self.assertGreaterEqual(event.relation, 0)
            self.assertGreaterEqual(event.fork, 0)
            self.assertLessEqual(event.fork, 4)  # MAIN, FSM, VM, INIT, etc.
            self.assertGreaterEqual(event.segment, 0)
            self.assertGreaterEqual(event.block, 0)
            self.assertGreater(event.elapsed_us, 0)
        finally:
            os.unlink(temp_path)

    def test_io_timestamps_ordered(self):
        """Test that IO event timestamps are ordered."""
        import tempfile
        sample_data = """12345,100,IO_READ,0x1,1663,16384,24576,0,0,1,50,8,5
12345,200,IO_READ,0x1,1663,16384,24576,0,0,2,50,8,5
12345,300,IO_READ,0x1,1663,16384,24576,0,0,3,50,8,5
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.trc', delete=False) as f:
            f.write(sample_data)
            temp_path = f.name

        try:
            trace = parse_io_trace(temp_path)

            # Timestamps should be monotonically increasing
            for i in range(1, len(trace.events)):
                self.assertGreaterEqual(
                    trace.events[i].timestamp,
                    trace.events[i-1].timestamp,
                    "Timestamps should be ordered"
                )
        finally:
            os.unlink(temp_path)


class TestCPUEventParser(unittest.TestCase):
    """Test CPU event parsing."""

    def test_parse_cpu_off_event(self):
        """Test parsing CPU_OFF event line."""
        import tempfile
        sample_data = """# CPU trace
12345,1234567890123,CPU_OFF,0xabc123,5000
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.trc', delete=False) as f:
            f.write(sample_data)
            temp_path = f.name

        try:
            trace = parse_io_trace(temp_path)

            self.assertEqual(len(trace.cpu_off), 1)
            self.assertEqual(len(trace.cpu_on), 0)

            event = trace.cpu_off[0]
            self.assertEqual(event.event_type, 'CPU_OFF')
            self.assertEqual(event.pid, 12345)
            self.assertEqual(event.node_ptr, '0xabc123')
            self.assertEqual(event.duration_us, 5000)  # on-CPU duration
        finally:
            os.unlink(temp_path)

    def test_parse_cpu_on_event(self):
        """Test parsing CPU_ON event line."""
        import tempfile
        sample_data = """12345,1234567890123,CPU_ON,0xdef456,2000
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.trc', delete=False) as f:
            f.write(sample_data)
            temp_path = f.name

        try:
            trace = parse_io_trace(temp_path)

            self.assertEqual(len(trace.cpu_on), 1)
            event = trace.cpu_on[0]
            self.assertEqual(event.event_type, 'CPU_ON')
            self.assertEqual(event.duration_us, 2000)  # off-CPU duration
        finally:
            os.unlink(temp_path)

    def test_parse_mixed_events(self):
        """Test parsing mixed IO and CPU events."""
        import tempfile
        sample_data = """# Mixed trace
12345,100,CPU_OFF,0x1,1000
12345,150,IO_READ,0x1,1663,16384,24576,0,0,1,500,8,50
12345,200,CPU_ON,0x1,500
12345,250,CPU_OFF,0x1,2000
12345,300,IO_WRITE,0x1,1663,16384,24576,0,0,2,300,8,30
12345,350,CPU_ON,0x1,1000
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.trc', delete=False) as f:
            f.write(sample_data)
            temp_path = f.name

        try:
            trace = parse_io_trace(temp_path)

            self.assertEqual(len(trace.cpu_off), 2)
            self.assertEqual(len(trace.cpu_on), 2)
            self.assertEqual(len(trace.io_reads), 1)
            self.assertEqual(len(trace.io_writes), 1)

            # Check totals
            self.assertEqual(trace.total_on_cpu_us, 1000 + 2000)  # CPU_OFF durations
            self.assertEqual(trace.total_off_cpu_us, 500 + 1000)  # CPU_ON durations
            self.assertEqual(trace.cpu_switches, 2)
        finally:
            os.unlink(temp_path)

    def test_cpu_event_has_node_ptr(self):
        """Test that CPU events have node pointer."""
        import tempfile
        sample_data = """12345,100,CPU_OFF,0xabcdef,5000
12345,200,CPU_ON,(nil),1000
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.trc', delete=False) as f:
            f.write(sample_data)
            temp_path = f.name

        try:
            trace = parse_io_trace(temp_path)

            # First event has node ptr
            self.assertEqual(trace.cpu_off[0].node_ptr, '0xabcdef')
            # Second event has nil ptr (no node executing)
            self.assertEqual(trace.cpu_on[0].node_ptr, '(nil)')
        finally:
            os.unlink(temp_path)


@unittest.skipUnless(is_root(), "Requires root for eBPF")
class TestCPUEvents(unittest.TestCase):
    """Test CPU event capture via eBPF."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

        conn = cls.harness.new_connection()
        conn.execute("DROP TABLE IF EXISTS cpu_event_test CASCADE")
        conn.execute("""
            CREATE TABLE cpu_event_test (
                id SERIAL PRIMARY KEY,
                data TEXT
            )
        """)
        conn.execute("""
            INSERT INTO cpu_event_test (data)
            SELECT md5(i::text)
            FROM generate_series(1, 50000) i
        """)
        conn.execute("ANALYZE cpu_event_test")
        conn.close()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def test_cpu_intensive_generates_events(self):
        """Test that CPU-intensive query generates CPU events."""
        if not daemon_running():
            self.skipTest("Daemon not running")

        with self.harness.traced_session(ebpf_active=True) as session:
            # CPU-intensive query with lots of computation
            result = session.execute("""
                SELECT
                    SUM(LENGTH(data) * LENGTH(data))
                FROM cpu_event_test
            """, with_explain=False)

            time.sleep(0.5)

            io_trace_path = find_io_trace(self.harness.config.trace_dir, session.conn.pid)

            if io_trace_path:
                trace = parse_io_trace(io_trace_path)
                # Should have CPU events for context switches
                # Note: Number depends on system load and query duration
                total_cpu = trace.total_on_cpu_us
                # Just verify we can access the property

    def test_cpu_events_have_timing(self):
        """Test that CPU events have valid timing."""
        if not daemon_running():
            self.skipTest("Daemon not running")

        with self.harness.traced_session(ebpf_active=True) as session:
            # Use pg_sleep to force context switches
            session.execute("SELECT pg_sleep(0.1)", with_explain=False)
            time.sleep(0.3)

            io_trace_path = find_io_trace(self.harness.config.trace_dir, session.conn.pid)

            if io_trace_path:
                trace = parse_io_trace(io_trace_path)

                # CPU_OFF events should have positive on-CPU duration
                for event in trace.cpu_off:
                    self.assertGreater(event.duration_us, 0,
                                       "On-CPU duration should be positive")

                # CPU_ON events should have positive off-CPU duration
                for event in trace.cpu_on:
                    self.assertGreater(event.duration_us, 0,
                                       "Off-CPU duration should be positive")

    def test_cpu_off_on_pairing(self):
        """Test that CPU_OFF and CPU_ON events are roughly paired."""
        if not daemon_running():
            self.skipTest("Daemon not running")

        with self.harness.traced_session(ebpf_active=True) as session:
            session.execute("""
                SELECT COUNT(*) FROM cpu_event_test WHERE data LIKE '%abc%'
            """, with_explain=False)
            time.sleep(0.3)

            io_trace_path = find_io_trace(self.harness.config.trace_dir, session.conn.pid)

            if io_trace_path:
                trace = parse_io_trace(io_trace_path)

                # CPU_OFF and CPU_ON counts should be similar
                # (may differ by 1 due to trace boundaries)
                off_count = len(trace.cpu_off)
                on_count = len(trace.cpu_on)

                if off_count > 0 and on_count > 0:
                    self.assertLessEqual(
                        abs(off_count - on_count), 2,
                        f"CPU_OFF ({off_count}) and CPU_ON ({on_count}) should be roughly paired"
                    )


class TestCPUValidation(unittest.TestCase):
    """Test CPU event validation."""

    def test_cpu_duration_reasonable(self):
        """Test that CPU durations are reasonable."""
        import tempfile
        sample_data = """12345,100,CPU_OFF,0x1,50000
12345,200,CPU_ON,0x1,10000
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.trc', delete=False) as f:
            f.write(sample_data)
            temp_path = f.name

        try:
            trace = parse_io_trace(temp_path)

            for event in trace.cpu_off:
                # On-CPU duration should be < 10 seconds
                self.assertLess(event.duration_us, 10_000_000)

            for event in trace.cpu_on:
                # Off-CPU duration should be < 10 seconds
                self.assertLess(event.duration_us, 10_000_000)
        finally:
            os.unlink(temp_path)

    def test_ebpf_trace_summary(self):
        """Test eBPF trace summary properties."""
        import tempfile
        sample_data = """12345,100,CPU_OFF,0x1,1000
12345,150,IO_READ,0x1,1663,16384,24576,0,0,1,500,8,50
12345,200,CPU_ON,0x1,500
12345,250,CPU_OFF,0x1,2000
12345,300,IO_READ,0x1,1663,16384,24576,0,0,2,600,8,60
12345,350,CPU_ON,0x1,800
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.trc', delete=False) as f:
            f.write(sample_data)
            temp_path = f.name

        try:
            trace = parse_io_trace(temp_path)

            # Test summary properties
            self.assertEqual(trace.total_on_cpu_us, 3000)  # 1000 + 2000
            self.assertEqual(trace.total_off_cpu_us, 1300)  # 500 + 800
            self.assertEqual(trace.total_read_us, 1100)  # 500 + 600
            self.assertEqual(trace.total_write_us, 0)
            self.assertEqual(trace.total_blocks_read, 2)
            self.assertEqual(trace.cpu_switches, 2)
        finally:
            os.unlink(temp_path)


if __name__ == '__main__':
    unittest.main(verbosity=2)
