#!/usr/bin/env python3
"""
Test trace_dir GUC - Directory configuration for trace files.

Tests:
1. Default trace_dir is relative to $PGDATA
2. Relative paths resolve to $PGDATA/relative_path
3. Absolute paths are used as-is
4. get_trace_dir() returns resolved absolute path
5. create_trace_dir() works with both relative and absolute paths
6. GUC validation rejects non-existent directories
7. Traces are written to the configured directory
"""

import unittest
import sys
import os
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(__file__))

from lib.pg_harness import PgHarness, PgConfig


class TestTraceDirGUC(unittest.TestCase):
    """Test pg_10046.trace_dir GUC parameter."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()
        # Get PGDATA for path verification
        conn = cls.harness.new_connection()
        result = conn.execute("SHOW data_directory")
        cls.pgdata = result.rows[0]['data_directory']
        conn.close()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def test_default_trace_dir_is_relative(self):
        """Test that default trace_dir is pg_10046_traces (relative)."""
        conn = self.harness.new_connection()
        result = conn.execute("SHOW pg_10046.trace_dir")
        trace_dir = result.rows[0]['pg_10046.trace_dir']
        conn.close()

        self.assertEqual(trace_dir, 'pg_10046_traces',
                        "Default trace_dir should be 'pg_10046_traces'")

    def test_get_trace_dir_returns_resolved_path(self):
        """Test that get_trace_dir() returns absolute resolved path."""
        conn = self.harness.new_connection()
        result = conn.execute("SELECT trace_10046.get_trace_dir() AS dir")
        resolved_dir = result.rows[0]['dir']
        conn.close()

        expected = os.path.join(self.pgdata, 'pg_10046_traces')
        self.assertEqual(resolved_dir, expected,
                        f"get_trace_dir() should return {expected}")

    def test_relative_path_resolves_to_pgdata(self):
        """Test that relative paths resolve to $PGDATA/path."""
        conn = self.harness.new_connection()

        # Create a relative path directory
        conn.execute("SELECT trace_10046.create_trace_dir('test_rel_traces')")
        conn.execute("SET pg_10046.trace_dir = 'test_rel_traces'")

        result = conn.execute("SELECT trace_10046.get_trace_dir() AS dir")
        resolved_dir = result.rows[0]['dir']
        conn.close()

        expected = os.path.join(self.pgdata, 'test_rel_traces')
        self.assertEqual(resolved_dir, expected,
                        f"Relative path should resolve to {expected}")

    def test_absolute_path_used_as_is(self):
        """Test that absolute paths are used without modification."""
        conn = self.harness.new_connection()

        # Create an absolute path directory
        abs_dir = '/tmp/pg_10046_test_abs'
        conn.execute(f"SELECT trace_10046.create_trace_dir('{abs_dir}')")
        conn.execute(f"SET pg_10046.trace_dir = '{abs_dir}'")

        result = conn.execute("SELECT trace_10046.get_trace_dir() AS dir")
        resolved_dir = result.rows[0]['dir']
        conn.close()

        self.assertEqual(resolved_dir, abs_dir,
                        f"Absolute path should be used as-is: {abs_dir}")


class TestCreateTraceDir(unittest.TestCase):
    """Test trace_10046.create_trace_dir() function."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()
        conn = cls.harness.new_connection()
        result = conn.execute("SHOW data_directory")
        cls.pgdata = result.rows[0]['data_directory']
        conn.close()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def test_create_relative_dir(self):
        """Test creating a directory with relative path."""
        conn = self.harness.new_connection()
        result = conn.execute(
            "SELECT trace_10046.create_trace_dir('test_create_rel') AS success"
        )
        success = result.rows[0]['success']
        conn.close()

        self.assertTrue(success, "create_trace_dir should return true")

        expected_path = os.path.join(self.pgdata, 'test_create_rel')
        self.assertTrue(os.path.isdir(expected_path),
                       f"Directory should exist at {expected_path}")

    def test_create_absolute_dir(self):
        """Test creating a directory with absolute path."""
        abs_dir = '/tmp/pg_10046_test_create_abs'
        # Clean up first
        if os.path.exists(abs_dir):
            os.rmdir(abs_dir)

        conn = self.harness.new_connection()
        result = conn.execute(
            f"SELECT trace_10046.create_trace_dir('{abs_dir}') AS success"
        )
        success = result.rows[0]['success']
        conn.close()

        self.assertTrue(success, "create_trace_dir should return true")
        self.assertTrue(os.path.isdir(abs_dir),
                       f"Directory should exist at {abs_dir}")

    def test_create_existing_dir_returns_true(self):
        """Test that create_trace_dir returns true for existing directory."""
        conn = self.harness.new_connection()
        # Create twice - second should still succeed
        conn.execute("SELECT trace_10046.create_trace_dir('test_existing')")
        result = conn.execute(
            "SELECT trace_10046.create_trace_dir('test_existing') AS success"
        )
        success = result.rows[0]['success']
        conn.close()

        self.assertTrue(success, "create_trace_dir should return true for existing dir")

    def test_create_dir_fails_on_file(self):
        """Test that create_trace_dir fails when path is a file."""
        conn = self.harness.new_connection()
        result = conn.execute(
            "SELECT trace_10046.create_trace_dir('/etc/passwd') AS success"
        )
        success = result.rows[0]['success']
        conn.close()

        self.assertFalse(success, "create_trace_dir should return false for file path")


class TestTraceDirValidation(unittest.TestCase):
    """Test GUC validation for pg_10046.trace_dir."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def test_set_nonexistent_dir_fails(self):
        """Test that setting non-existent directory fails."""
        conn = self.harness.new_connection()
        result = conn.execute("SET pg_10046.trace_dir = '/nonexistent/path/12345'")
        conn.close()

        # The harness captures errors in result.error
        self.assertIsNotNone(result.error, "Should have error for non-existent dir")
        self.assertIn('does not exist', result.error.lower())

    def test_set_file_path_fails(self):
        """Test that setting a file path fails."""
        conn = self.harness.new_connection()
        result = conn.execute("SET pg_10046.trace_dir = '/etc/passwd'")
        conn.close()

        self.assertIsNotNone(result.error, "Should have error for file path")
        self.assertIn('not a directory', result.error.lower())

    def test_set_valid_relative_path_succeeds(self):
        """Test that setting valid relative path succeeds."""
        conn = self.harness.new_connection()
        conn.execute("SELECT trace_10046.create_trace_dir('test_valid_rel')")

        # Should not raise
        conn.execute("SET pg_10046.trace_dir = 'test_valid_rel'")
        result = conn.execute("SHOW pg_10046.trace_dir")

        conn.close()
        self.assertEqual(result.rows[0]['pg_10046.trace_dir'], 'test_valid_rel')

    def test_set_valid_absolute_path_succeeds(self):
        """Test that setting valid absolute path succeeds."""
        abs_dir = '/tmp/pg_10046_test_valid_abs'

        conn = self.harness.new_connection()
        conn.execute(f"SELECT trace_10046.create_trace_dir('{abs_dir}')")

        # Should not raise
        conn.execute(f"SET pg_10046.trace_dir = '{abs_dir}'")
        result = conn.execute("SHOW pg_10046.trace_dir")

        conn.close()
        self.assertEqual(result.rows[0]['pg_10046.trace_dir'], abs_dir)


class TestTraceDirTracing(unittest.TestCase):
    """Test that traces are written to configured directory."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()
        conn = cls.harness.new_connection()
        result = conn.execute("SHOW data_directory")
        cls.pgdata = result.rows[0]['data_directory']
        conn.close()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def test_trace_written_to_default_dir(self):
        """Test that trace is written to default directory."""
        import glob
        import time

        trace_dir = os.path.join(self.pgdata, 'pg_10046_traces')

        # Create default dir if doesn't exist
        conn = self.harness.new_connection()
        conn.execute("SELECT trace_10046.create_trace_dir('pg_10046_traces')")

        # Clean existing traces
        for f in glob.glob(os.path.join(trace_dir, 'pg_10046_*.trc')):
            os.remove(f)

        conn.execute("RESET pg_10046.trace_dir")
        conn.execute("SET pg_10046.enabled = on")
        conn.execute("SELECT 'trace_dir_test_default' AS marker")
        conn.execute("SET pg_10046.enabled = off")
        conn.close()

        time.sleep(2)  # Wait for async flush

        traces = glob.glob(os.path.join(trace_dir, 'pg_10046_*.trc'))
        self.assertGreater(len(traces), 0,
                          f"Expected trace file in {trace_dir}")

        # Verify content
        with open(traces[-1], 'r') as f:
            content = f.read()
        self.assertIn('trace_dir_test_default', content)

    def test_trace_written_to_custom_dir(self):
        """Test that trace is written to custom directory."""
        import glob
        import time

        custom_dir = '/tmp/pg_10046_custom_trace_test'

        conn = self.harness.new_connection()
        conn.execute(f"SELECT trace_10046.create_trace_dir('{custom_dir}')")

        # Clean existing traces
        for f in glob.glob(os.path.join(custom_dir, 'pg_10046_*.trc')):
            os.remove(f)

        conn.execute(f"SET pg_10046.trace_dir = '{custom_dir}'")
        conn.execute("SET pg_10046.enabled = on")
        conn.execute("SELECT 'trace_dir_test_custom' AS marker")
        conn.execute("SET pg_10046.enabled = off")
        conn.close()

        time.sleep(2)  # Wait for async flush

        traces = glob.glob(os.path.join(custom_dir, 'pg_10046_*.trc'))
        self.assertGreater(len(traces), 0,
                          f"Expected trace file in {custom_dir}")

        # Verify content
        with open(traces[-1], 'r') as f:
            content = f.read()
        self.assertIn('trace_dir_test_custom', content)


if __name__ == '__main__':
    unittest.main(verbosity=2)
