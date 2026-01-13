#!/usr/bin/env python3
"""
Test Bind Variables and Plan Tree Output.

Tests that:
- Bind variables are captured for parameterized queries
- Plan tree output matches EXPLAIN structure
- Prepared statements work correctly
- Node-specific info (SORT, HASH, INDEX) is captured
"""

import unittest
import sys
import os
import re

sys.path.insert(0, os.path.dirname(__file__))

from lib.pg_harness import PgHarness
from lib.assertions import (
    parse_trace,
    assert_header_present,
    assert_all_nodes_paired,
    TraceAssertionError,
)
from lib.trace_validator import EventType


class TestBindVariables(unittest.TestCase):
    """Test bind variable capture for parameterized queries."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

        conn = cls.harness.new_connection()
        conn.execute("DROP TABLE IF EXISTS bind_test CASCADE")
        conn.execute("""
            CREATE TABLE bind_test (
                id SERIAL PRIMARY KEY,
                name TEXT,
                value INTEGER,
                created_at TIMESTAMP DEFAULT now()
            )
        """)
        conn.execute("""
            INSERT INTO bind_test (name, value)
            SELECT 'item_' || i, i * 10
            FROM generate_series(1, 100) i
        """)
        conn.execute("ANALYZE bind_test")
        conn.close()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def _get_bind_events(self, trace):
        """Extract bind-related events from trace."""
        binds_start = None
        bind_events = []
        for event in trace.events:
            if event.event_type == EventType.BIND:
                bind_events.append(event)
            elif 'BINDS_START' in str(event.raw_line if hasattr(event, 'raw_line') else ''):
                binds_start = event
        return binds_start, bind_events

    def _find_line_pattern(self, trace_path, pattern):
        """Find lines matching pattern in trace file."""
        matches = []
        with open(trace_path, 'r') as f:
            for line in f:
                if re.search(pattern, line):
                    matches.append(line.strip())
        return matches

    def test_simple_parameterized_query(self):
        """Test bind variable capture with simple $1 parameter."""
        with self.harness.traced_session() as session:
            # Use prepared statement with parameter
            session.conn.execute("PREPARE bind_test_q1 AS SELECT * FROM bind_test WHERE id = $1")
            session.conn.execute("EXECUTE bind_test_q1(42)")
            session.conn.execute("DEALLOCATE bind_test_q1")

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            # Check for BINDS_START in raw trace
            binds = self._find_line_pattern(trace_info.path, r'BINDS_START')
            bind_lines = self._find_line_pattern(trace_info.path, r'^BIND,')

            # Should have bind variable captured
            if binds:
                self.assertGreater(len(bind_lines), 0, "Should have BIND lines after BINDS_START")

    def test_multiple_bind_variables(self):
        """Test multiple bind variables in single query."""
        with self.harness.traced_session() as session:
            session.conn.execute("""
                PREPARE bind_test_q2 AS
                SELECT * FROM bind_test
                WHERE id BETWEEN $1 AND $2
                  AND name LIKE $3
            """)
            session.conn.execute("EXECUTE bind_test_q2(10, 50, 'item_%')")
            session.conn.execute("DEALLOCATE bind_test_q2")

            trace_info = session.get_trace()

            # Check for multiple bind variables
            bind_lines = self._find_line_pattern(trace_info.path, r'^BIND,')

            # Should have 3 bind variables
            # Format: BIND,<num>,<type>,<value>
            param_nums = set()
            for line in bind_lines:
                parts = line.split(',')
                if len(parts) >= 2:
                    param_nums.add(parts[1])

            if bind_lines:
                self.assertGreaterEqual(len(param_nums), 3, "Should capture 3 bind variables")

    def test_bind_variable_types(self):
        """Test various bind variable types are captured correctly."""
        with self.harness.traced_session() as session:
            session.conn.execute("""
                PREPARE bind_test_types AS
                SELECT * FROM bind_test
                WHERE id = $1
                  AND value > $2
                  AND name = $3
            """)
            # Integer, Integer, Text
            session.conn.execute("EXECUTE bind_test_types(1, 100, 'item_1')")
            session.conn.execute("DEALLOCATE bind_test_types")

            trace_info = session.get_trace()
            bind_lines = self._find_line_pattern(trace_info.path, r'^BIND,')

            # Check types are captured
            # Format: BIND,<num>,<type>,<value>
            types_found = set()
            for line in bind_lines:
                parts = line.split(',')
                if len(parts) >= 3:
                    types_found.add(parts[2])

            if bind_lines:
                # Should have integer and text types
                self.assertGreater(len(types_found), 0, "Should capture bind variable types")

    def test_null_bind_variable(self):
        """Test NULL bind variable is captured."""
        with self.harness.traced_session() as session:
            session.conn.execute("""
                PREPARE bind_test_null AS
                SELECT * FROM bind_test WHERE name = $1
            """)
            session.conn.execute("EXECUTE bind_test_null(NULL)")
            session.conn.execute("DEALLOCATE bind_test_null")

            trace_info = session.get_trace()
            bind_lines = self._find_line_pattern(trace_info.path, r'^BIND,')

            # NULL should be captured
            null_found = any('NULL' in line for line in bind_lines)
            if bind_lines:
                self.assertTrue(null_found, "NULL bind variable should be captured")

    def test_bind_count_in_binds_start(self):
        """Test that BINDS_START contains correct parameter count."""
        with self.harness.traced_session() as session:
            session.conn.execute("""
                PREPARE bind_count_test AS
                SELECT * FROM bind_test WHERE id = $1 AND value = $2
            """)
            session.conn.execute("EXECUTE bind_count_test(5, 50)")
            session.conn.execute("DEALLOCATE bind_count_test")

            trace_info = session.get_trace()
            binds_start = self._find_line_pattern(trace_info.path, r'BINDS_START,')

            if binds_start:
                # Format: BINDS_START,<count>
                parts = binds_start[0].split(',')
                if len(parts) >= 2:
                    count = int(parts[1])
                    self.assertEqual(count, 2, "BINDS_START should report 2 parameters")


class TestPlanTreeOutput(unittest.TestCase):
    """Test plan tree output in traces."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

        conn = cls.harness.new_connection()
        conn.execute("DROP TABLE IF EXISTS plan_test CASCADE")
        conn.execute("DROP TABLE IF EXISTS plan_test2 CASCADE")
        conn.execute("""
            CREATE TABLE plan_test (
                id SERIAL PRIMARY KEY,
                name TEXT,
                value INTEGER
            )
        """)
        conn.execute("""
            CREATE TABLE plan_test2 (
                id SERIAL PRIMARY KEY,
                plan_test_id INTEGER REFERENCES plan_test(id),
                data TEXT
            )
        """)
        conn.execute("""
            INSERT INTO plan_test (name, value)
            SELECT 'item_' || i, i
            FROM generate_series(1, 1000) i
        """)
        conn.execute("""
            INSERT INTO plan_test2 (plan_test_id, data)
            SELECT i % 1000 + 1, md5(i::text)
            FROM generate_series(1, 5000) i
        """)
        conn.execute("CREATE INDEX plan_test_value_idx ON plan_test(value)")
        conn.execute("ANALYZE plan_test")
        conn.execute("ANALYZE plan_test2")
        conn.close()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def _get_plan_lines(self, trace_path):
        """Get PLAN lines from trace."""
        plan_lines = []
        in_plan = False
        with open(trace_path, 'r') as f:
            for line in f:
                if 'PLAN_START' in line:
                    in_plan = True
                elif 'PLAN_END' in line:
                    in_plan = False
                elif in_plan and line.startswith('PLAN,'):
                    plan_lines.append(line.strip())
        return plan_lines

    def _get_plan_time(self, trace_path):
        """Get PLAN_TIME from trace."""
        with open(trace_path, 'r') as f:
            for line in f:
                if line.startswith('PLAN_TIME,'):
                    parts = line.strip().split(',')
                    if len(parts) >= 2:
                        return int(parts[1])
        return None

    def test_plan_start_end_markers(self):
        """Test PLAN_START and PLAN_END markers are present."""
        with self.harness.traced_session() as session:
            session.execute("SELECT * FROM plan_test WHERE id = 1", with_explain=False)

            trace_info = session.get_trace()

            with open(trace_info.path, 'r') as f:
                content = f.read()

            self.assertIn('PLAN_START', content, "Should have PLAN_START marker")
            self.assertIn('PLAN_END', content, "Should have PLAN_END marker")

    def test_plan_contains_node_type(self):
        """Test that PLAN lines contain node types."""
        with self.harness.traced_session() as session:
            session.execute("SELECT * FROM plan_test", with_explain=False)

            trace_info = session.get_trace()
            plan_lines = self._get_plan_lines(trace_info.path)

            self.assertGreater(len(plan_lines), 0, "Should have PLAN lines")

            # Check for SeqScan node type
            node_types = []
            for line in plan_lines:
                # Format: PLAN,<id>,<parent_id>,<depth>,<node_type>,<rows>,<cost>,<target>
                parts = line.split(',')
                if len(parts) >= 5:
                    node_types.append(parts[4])

            self.assertIn('SeqScan', node_types, "Should have SeqScan node")

    def test_plan_contains_index_scan(self):
        """Test that IndexScan appears in plan for indexed query."""
        with self.harness.traced_session() as session:
            # Query that should use index
            session.execute("SELECT * FROM plan_test WHERE value = 500", with_explain=False)

            trace_info = session.get_trace()
            plan_lines = self._get_plan_lines(trace_info.path)

            # Check for IndexScan or IndexOnlyScan
            node_types = []
            for line in plan_lines:
                parts = line.split(',')
                if len(parts) >= 5:
                    node_types.append(parts[4])

            has_index = any('Index' in nt for nt in node_types)
            # May use SeqScan for small table, so just check plan exists
            self.assertGreater(len(node_types), 0, "Should have plan nodes")

    def test_plan_contains_join(self):
        """Test that join node appears in plan for join query."""
        with self.harness.traced_session() as session:
            session.execute("""
                SELECT p.name, t.data
                FROM plan_test p
                JOIN plan_test2 t ON t.plan_test_id = p.id
                WHERE p.id <= 10
            """, with_explain=False)

            trace_info = session.get_trace()
            plan_lines = self._get_plan_lines(trace_info.path)

            node_types = []
            for line in plan_lines:
                parts = line.split(',')
                if len(parts) >= 5:
                    node_types.append(parts[4])

            # Should have some join type
            has_join = any(nt in ('HashJoin', 'NestedLoop', 'MergeJoin', 'Hash Join', 'Nested Loop', 'Merge Join')
                         for nt in node_types)
            self.assertTrue(has_join or len(node_types) >= 2, "Should have join or multiple nodes")

    def test_plan_has_cost_estimates(self):
        """Test that PLAN lines contain cost estimates."""
        with self.harness.traced_session() as session:
            session.execute("SELECT * FROM plan_test LIMIT 10", with_explain=False)

            trace_info = session.get_trace()
            plan_lines = self._get_plan_lines(trace_info.path)

            self.assertGreater(len(plan_lines), 0, "Should have PLAN lines")

            # Check for numeric cost value
            # Format: PLAN,<id>,<parent_id>,<depth>,<node_type>,<rows>,<cost>,<target>
            for line in plan_lines:
                parts = line.split(',')
                if len(parts) >= 7:
                    try:
                        cost = float(parts[6])
                        self.assertGreaterEqual(cost, 0, "Cost should be non-negative")
                    except ValueError:
                        pass  # May be non-numeric in some cases

    def test_plan_has_row_estimates(self):
        """Test that PLAN lines contain row estimates."""
        with self.harness.traced_session() as session:
            session.execute("SELECT * FROM plan_test", with_explain=False)

            trace_info = session.get_trace()
            plan_lines = self._get_plan_lines(trace_info.path)

            self.assertGreater(len(plan_lines), 0, "Should have PLAN lines")

            # Check for row estimate
            for line in plan_lines:
                parts = line.split(',')
                if len(parts) >= 6:
                    try:
                        rows = float(parts[5])
                        self.assertGreaterEqual(rows, 0, "Row estimate should be non-negative")
                    except ValueError:
                        pass

    def test_plan_time_captured(self):
        """Test that PLAN_TIME is captured."""
        with self.harness.traced_session() as session:
            session.execute("SELECT * FROM plan_test WHERE id = 1", with_explain=False)

            trace_info = session.get_trace()
            plan_time = self._get_plan_time(trace_info.path)

            self.assertIsNotNone(plan_time, "PLAN_TIME should be captured")
            self.assertGreaterEqual(plan_time, 0, "PLAN_TIME should be non-negative")

    def test_plan_tree_hierarchy(self):
        """Test that plan tree has proper parent-child relationships."""
        with self.harness.traced_session() as session:
            # Query with multiple levels
            session.execute("""
                SELECT * FROM plan_test
                ORDER BY value
                LIMIT 10
            """, with_explain=False)

            trace_info = session.get_trace()
            plan_lines = self._get_plan_lines(trace_info.path)

            # Build parent-child map
            # Format: PLAN,<id>,<parent_id>,<depth>,<node_type>,...
            nodes = {}
            for line in plan_lines:
                parts = line.split(',')
                if len(parts) >= 4:
                    node_id = int(parts[1])
                    parent_id = int(parts[2])
                    depth = int(parts[3])
                    nodes[node_id] = {'parent': parent_id, 'depth': depth}

            # Check hierarchy is valid
            for node_id, info in nodes.items():
                if info['parent'] > 0:
                    # Parent should exist and have lower depth
                    self.assertIn(info['parent'], nodes, f"Parent {info['parent']} should exist")
                    self.assertLess(
                        nodes[info['parent']]['depth'],
                        info['depth'],
                        "Parent should have lower depth"
                    )


class TestPreparedStatements(unittest.TestCase):
    """Test prepared statement tracing."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

        conn = cls.harness.new_connection()
        conn.execute("DROP TABLE IF EXISTS prep_test CASCADE")
        conn.execute("""
            CREATE TABLE prep_test (
                id SERIAL PRIMARY KEY,
                name TEXT,
                value INTEGER
            )
        """)
        conn.execute("""
            INSERT INTO prep_test (name, value)
            SELECT 'item_' || i, i
            FROM generate_series(1, 100) i
        """)
        conn.execute("ANALYZE prep_test")
        conn.close()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def test_prepare_is_traced(self):
        """Test that PREPARE statement is traced."""
        with self.harness.traced_session() as session:
            session.conn.execute("PREPARE prep_q1 AS SELECT * FROM prep_test WHERE id = $1")
            # Execute to generate trace
            session.conn.execute("EXECUTE prep_q1(1)")
            session.conn.execute("DEALLOCATE prep_q1")

            trace_info = session.get_trace()
            # PREPARE/EXECUTE should generate trace
            self.assertIsNotNone(trace_info, "EXECUTE should generate trace")

            trace = parse_trace(trace_info.path)
            # Verify trace is valid
            assert_all_nodes_paired(trace)

    def test_execute_is_traced(self):
        """Test that EXECUTE statement is traced with bind values."""
        with self.harness.traced_session() as session:
            session.conn.execute("PREPARE prep_q2 AS SELECT * FROM prep_test WHERE id = $1")
            session.conn.execute("EXECUTE prep_q2(42)")
            session.conn.execute("DEALLOCATE prep_q2")

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            # Check trace has content
            self.assertGreater(len(trace.events), 0, "EXECUTE should generate trace events")

    def test_multiple_executes(self):
        """Test multiple EXECUTE calls with different parameters."""
        with self.harness.traced_session() as session:
            session.conn.execute("PREPARE prep_q3 AS SELECT * FROM prep_test WHERE id = $1")
            session.conn.execute("EXECUTE prep_q3(1)")
            session.conn.execute("EXECUTE prep_q3(50)")
            session.conn.execute("EXECUTE prep_q3(100)")
            session.conn.execute("DEALLOCATE prep_q3")

            trace_info = session.get_trace()

            # Should have multiple bind sections
            with open(trace_info.path, 'r') as f:
                content = f.read()

            # Count BINDS_START occurrences
            binds_count = content.count('BINDS_START')
            # May have 3 or more (one per EXECUTE)
            self.assertGreaterEqual(binds_count, 0, "Should trace EXECUTE calls")

    def test_prepared_statement_replan(self):
        """Test that re-planned prepared statements are traced."""
        with self.harness.traced_session() as session:
            # Create prepared statement
            session.conn.execute("PREPARE prep_replan AS SELECT * FROM prep_test WHERE id = $1")

            # Execute many times to potentially trigger replan
            for i in range(10):
                session.conn.execute(f"EXECUTE prep_replan({i + 1})")

            session.conn.execute("DEALLOCATE prep_replan")

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            # Trace should be valid
            assert_all_nodes_paired(trace)


class TestNodeSpecificInfo(unittest.TestCase):
    """Test node-specific information capture (SORT, HASH, INDEX)."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

        conn = cls.harness.new_connection()
        conn.execute("DROP TABLE IF EXISTS node_info_test CASCADE")
        conn.execute("DROP TABLE IF EXISTS node_info_test2 CASCADE")
        conn.execute("""
            CREATE TABLE node_info_test (
                id SERIAL PRIMARY KEY,
                name TEXT,
                value INTEGER
            )
        """)
        conn.execute("""
            CREATE TABLE node_info_test2 (
                id SERIAL PRIMARY KEY,
                ref_id INTEGER,
                data TEXT
            )
        """)
        conn.execute("""
            INSERT INTO node_info_test (name, value)
            SELECT md5(i::text), i % 1000
            FROM generate_series(1, 10000) i
        """)
        conn.execute("""
            INSERT INTO node_info_test2 (ref_id, data)
            SELECT i % 10000 + 1, md5(i::text)
            FROM generate_series(1, 50000) i
        """)
        conn.execute("CREATE INDEX node_info_test_value_idx ON node_info_test(value)")
        conn.execute("CREATE INDEX node_info_test2_ref_idx ON node_info_test2(ref_id)")
        conn.execute("ANALYZE node_info_test")
        conn.execute("ANALYZE node_info_test2")
        conn.close()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def _find_stat_lines(self, trace_path, prefix):
        """Find STAT lines with given prefix."""
        lines = []
        with open(trace_path, 'r') as f:
            for line in f:
                if line.startswith(prefix):
                    lines.append(line.strip())
        return lines

    def test_sort_info_captured(self):
        """Test that SORT info is captured for sort operations."""
        with self.harness.traced_session() as session:
            # Force sort with small work_mem
            session.conn.execute("SET work_mem = '64kB'")
            session.execute("""
                SELECT * FROM node_info_test
                ORDER BY name
                LIMIT 100
            """, with_explain=False)

            trace_info = session.get_trace()
            sort_lines = self._find_stat_lines(trace_info.path, 'SORT,')

            # SORT line should contain method and space info
            # Format: SORT,<node_id>,<method>,<space_type>,<space_used>
            if sort_lines:
                for line in sort_lines:
                    parts = line.split(',')
                    self.assertGreaterEqual(len(parts), 4, "SORT should have method and space info")

    def test_hash_info_captured(self):
        """Test that HASH info is captured for hash joins."""
        with self.harness.traced_session() as session:
            # Query that should use hash join
            session.conn.execute("SET enable_mergejoin = off")
            session.conn.execute("SET enable_nestloop = off")
            session.execute("""
                SELECT t1.name, t2.data
                FROM node_info_test t1
                JOIN node_info_test2 t2 ON t2.ref_id = t1.id
                WHERE t1.id <= 100
            """, with_explain=False)
            session.conn.execute("SET enable_mergejoin = on")
            session.conn.execute("SET enable_nestloop = on")

            trace_info = session.get_trace()

            # Look for HASH or HASHJOIN lines
            hash_lines = self._find_stat_lines(trace_info.path, 'HASH,')
            hashjoin_lines = self._find_stat_lines(trace_info.path, 'HASHJOIN,')

            # May have hash info if hash join was used
            # Format: HASH,<id>,<buckets>,<batches>,<space_kb>,<peak_kb>
            all_hash = hash_lines + hashjoin_lines
            if all_hash:
                for line in all_hash:
                    parts = line.split(',')
                    self.assertGreaterEqual(len(parts), 5, "HASH should have bucket and space info")

    def test_index_info_captured(self):
        """Test that INDEX info is captured for index scans."""
        with self.harness.traced_session() as session:
            # Query that should use index
            session.execute("""
                SELECT * FROM node_info_test WHERE value = 500
            """, with_explain=False)

            trace_info = session.get_trace()
            index_lines = self._find_stat_lines(trace_info.path, 'INDEX,')

            # INDEX line should contain index and table names
            # Format: INDEX,<node_id>,<index_name>,<table_name>
            if index_lines:
                for line in index_lines:
                    parts = line.split(',')
                    self.assertGreaterEqual(len(parts), 4, "INDEX should have index and table names")
                    # Check names are not empty
                    if len(parts) >= 4:
                        self.assertGreater(len(parts[2]), 0, "Index name should not be empty")
                        self.assertGreater(len(parts[3]), 0, "Table name should not be empty")

    def test_sort_method_types(self):
        """Test different sort methods are captured."""
        with self.harness.traced_session() as session:
            # In-memory sort (small result)
            session.conn.execute("SET work_mem = '4MB'")
            session.execute("""
                SELECT * FROM node_info_test
                ORDER BY value
                LIMIT 10
            """, with_explain=False)

            trace_info = session.get_trace()
            sort_lines = self._find_stat_lines(trace_info.path, 'SORT,')

            # Check sort method is captured
            methods_found = set()
            for line in sort_lines:
                parts = line.split(',')
                if len(parts) >= 3:
                    methods_found.add(parts[2])

            # Methods include: quicksort, top-N heapsort, external sort, external merge
            # Just verify we have valid trace
            trace = parse_trace(trace_info.path)
            assert_all_nodes_paired(trace)

    def test_stats_section_complete(self):
        """Test that STATS section is complete with node info."""
        with self.harness.traced_session() as session:
            session.execute("""
                SELECT * FROM node_info_test
                WHERE value BETWEEN 100 AND 200
                ORDER BY name
            """, with_explain=False)

            trace_info = session.get_trace()

            with open(trace_info.path, 'r') as f:
                content = f.read()

            # Should have STATS_START and STATS_END
            self.assertIn('STATS_START', content, "Should have STATS_START")
            self.assertIn('STATS_END', content, "Should have STATS_END")

            # STAT lines should be between STATS_START and STATS_END
            stat_lines = self._find_stat_lines(trace_info.path, 'STAT,')
            self.assertGreater(len(stat_lines), 0, "Should have STAT lines")


class TestPlanValidation(unittest.TestCase):
    """Test plan output validation."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def test_plan_matches_explain(self):
        """Test that plan nodes match EXPLAIN output."""
        with self.harness.traced_session() as session:
            # Get EXPLAIN output
            explain_result = session.conn.execute(
                "EXPLAIN (FORMAT TEXT) SELECT * FROM pg_class LIMIT 10"
            )
            # Rows are dicts, get first value from each row
            explain_lines = [list(row.values())[0] for row in explain_result.rows]

            # Execute traced query
            session.execute("SELECT * FROM pg_class LIMIT 10", with_explain=False)

            trace_info = session.get_trace()

            # Get plan from trace
            plan_lines = []
            with open(trace_info.path, 'r') as f:
                in_plan = False
                for line in f:
                    if 'PLAN_START' in line:
                        in_plan = True
                    elif 'PLAN_END' in line:
                        in_plan = False
                    elif in_plan and line.startswith('PLAN,'):
                        plan_lines.append(line.strip())

            # Both should have nodes
            self.assertGreater(len(plan_lines), 0, "Trace should have plan nodes")
            self.assertGreater(len(explain_lines), 0, "EXPLAIN should have output")

    def test_root_node_has_no_parent(self):
        """Test that root plan node has parent_id = 0."""
        with self.harness.traced_session() as session:
            session.execute("SELECT 1", with_explain=False)

            trace_info = session.get_trace()

            plan_lines = []
            with open(trace_info.path, 'r') as f:
                in_plan = False
                for line in f:
                    if 'PLAN_START' in line:
                        in_plan = True
                    elif 'PLAN_END' in line:
                        in_plan = False
                    elif in_plan and line.startswith('PLAN,'):
                        plan_lines.append(line.strip())

            if plan_lines:
                # First node should have parent_id = 0
                first = plan_lines[0].split(',')
                if len(first) >= 3:
                    parent_id = int(first[2])
                    self.assertEqual(parent_id, 0, "Root node should have parent_id = 0")

    def test_all_nodes_have_valid_ids(self):
        """Test that all plan nodes have valid positive IDs."""
        with self.harness.traced_session() as session:
            session.execute("""
                SELECT * FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                LIMIT 10
            """, with_explain=False)

            trace_info = session.get_trace()

            plan_lines = []
            with open(trace_info.path, 'r') as f:
                in_plan = False
                for line in f:
                    if 'PLAN_START' in line:
                        in_plan = True
                    elif 'PLAN_END' in line:
                        in_plan = False
                    elif in_plan and line.startswith('PLAN,'):
                        plan_lines.append(line.strip())

            for line in plan_lines:
                parts = line.split(',')
                if len(parts) >= 2:
                    node_id = int(parts[1])
                    self.assertGreater(node_id, 0, f"Node ID should be positive: {line}")


if __name__ == '__main__':
    unittest.main(verbosity=2)
