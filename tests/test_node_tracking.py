#!/usr/bin/env python3
"""
Test Node Tracking - NODE_START/NODE_END matching tests.

Tests that:
- Every NODE_START has a matching NODE_END
- Node execution order is correct (depth-first)
- Complex query plans with many nodes are tracked correctly
- Nested loops, hash joins, merge joins all paired properly
- LIMIT queries properly cascade NODE_END events
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from lib.pg_harness import PgHarness
from lib.assertions import (
    parse_trace,
    assert_all_nodes_paired,
    assert_node_timing_valid,
    assert_node_types_present,
    assert_basic_trace_correctness,
    TraceAssertionError,
)
from lib.trace_validator import EventType


class TestNodePairing(unittest.TestCase):
    """Test that NODE_START/NODE_END events are properly paired."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

        conn = cls.harness.new_connection()
        conn.execute("DROP TABLE IF EXISTS orders CASCADE")
        conn.execute("DROP TABLE IF EXISTS customers CASCADE")
        conn.execute("DROP TABLE IF EXISTS products CASCADE")

        # Create test tables for joins
        conn.execute("""
            CREATE TABLE customers (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                region TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE products (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                price NUMERIC(10,2)
            )
        """)
        conn.execute("""
            CREATE TABLE orders (
                id SERIAL PRIMARY KEY,
                customer_id INTEGER REFERENCES customers(id),
                product_id INTEGER REFERENCES products(id),
                quantity INTEGER,
                order_date DATE DEFAULT CURRENT_DATE
            )
        """)

        # Insert test data
        conn.execute("""
            INSERT INTO customers (name, region)
            SELECT 'Customer_' || i,
                   CASE i % 4 WHEN 0 THEN 'North' WHEN 1 THEN 'South'
                              WHEN 2 THEN 'East' ELSE 'West' END
            FROM generate_series(1, 1000) i
        """)
        conn.execute("""
            INSERT INTO products (name, price)
            SELECT 'Product_' || i, (i * 9.99)::numeric(10,2)
            FROM generate_series(1, 100) i
        """)
        conn.execute("""
            INSERT INTO orders (customer_id, product_id, quantity)
            SELECT
                (i % 1000) + 1,
                (i % 100) + 1,
                (i % 10) + 1
            FROM generate_series(1, 10000) i
        """)

        conn.execute("ANALYZE customers")
        conn.execute("ANALYZE products")
        conn.execute("ANALYZE orders")
        conn.close()

    @classmethod
    def tearDownClass(cls):
        # Don't drop tables - other tests may use them
        cls.harness.cleanup()

    def test_simple_join(self):
        """Test two-table join node pairing."""
        with self.harness.traced_session() as session:
            session.execute("""
                SELECT c.name, COUNT(o.id) as order_count
                FROM customers c
                JOIN orders o ON o.customer_id = c.id
                GROUP BY c.name
                LIMIT 10
            """)

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            # All nodes must be paired
            assert_all_nodes_paired(trace)
            assert_node_timing_valid(trace)

    def test_three_way_join(self):
        """Test three-table join node pairing."""
        with self.harness.traced_session() as session:
            session.execute("""
                SELECT c.name, p.name, SUM(o.quantity)
                FROM customers c
                JOIN orders o ON o.customer_id = c.id
                JOIN products p ON p.id = o.product_id
                GROUP BY c.name, p.name
                LIMIT 100
            """)

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            assert_all_nodes_paired(trace)
            assert_node_timing_valid(trace)

            # Should have multiple nodes (at least 3 scans + 2 joins + aggregate + limit)
            self.assertGreaterEqual(len(trace.node_starts), 5)

    def test_hash_join(self):
        """Test Hash Join node tracking."""
        with self.harness.traced_session() as session:
            # Force hash join
            session.conn.execute("SET enable_nestloop = off")
            session.conn.execute("SET enable_mergejoin = off")

            session.execute("""
                SELECT c.name, o.id
                FROM customers c
                JOIN orders o ON o.customer_id = c.id
                WHERE c.region = 'North'
            """)

            session.conn.execute("SET enable_nestloop = on")
            session.conn.execute("SET enable_mergejoin = on")

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            assert_all_nodes_paired(trace)

    def test_nested_loop(self):
        """Test Nested Loop node tracking."""
        with self.harness.traced_session() as session:
            # Force nested loop
            session.conn.execute("SET enable_hashjoin = off")
            session.conn.execute("SET enable_mergejoin = off")

            session.execute("""
                SELECT c.name, o.id
                FROM customers c
                JOIN orders o ON o.customer_id = c.id
                WHERE c.id <= 5
            """)

            session.conn.execute("SET enable_hashjoin = on")
            session.conn.execute("SET enable_mergejoin = on")

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            assert_all_nodes_paired(trace)

    def test_merge_join(self):
        """Test Merge Join node tracking."""
        with self.harness.traced_session() as session:
            # Force merge join
            session.conn.execute("SET enable_hashjoin = off")
            session.conn.execute("SET enable_nestloop = off")

            session.execute("""
                SELECT c.name, o.id
                FROM customers c
                JOIN orders o ON o.customer_id = c.id
                ORDER BY c.id
            """)

            session.conn.execute("SET enable_hashjoin = on")
            session.conn.execute("SET enable_nestloop = on")

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            assert_all_nodes_paired(trace)

    def test_subquery(self):
        """Test subquery node tracking."""
        with self.harness.traced_session() as session:
            session.execute("""
                SELECT c.name
                FROM customers c
                WHERE c.id IN (
                    SELECT customer_id
                    FROM orders
                    GROUP BY customer_id
                    HAVING COUNT(*) > 5
                )
            """)

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            assert_all_nodes_paired(trace)

    def test_cte_query(self):
        """Test CTE (WITH clause) node tracking."""
        with self.harness.traced_session() as session:
            session.execute("""
                WITH top_customers AS (
                    SELECT customer_id, COUNT(*) as cnt
                    FROM orders
                    GROUP BY customer_id
                    ORDER BY cnt DESC
                    LIMIT 10
                )
                SELECT c.name, tc.cnt
                FROM top_customers tc
                JOIN customers c ON c.id = tc.customer_id
            """)

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            assert_all_nodes_paired(trace)

    def test_union_query(self):
        """Test UNION query node tracking."""
        with self.harness.traced_session() as session:
            session.execute("""
                SELECT name, 'customer' as type FROM customers WHERE id <= 10
                UNION ALL
                SELECT name, 'product' as type FROM products WHERE id <= 10
            """)

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            assert_all_nodes_paired(trace)


class TestLimitCascade(unittest.TestCase):
    """Test that LIMIT properly cascades NODE_END events."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

        conn = cls.harness.new_connection()
        conn.execute("DROP TABLE IF EXISTS limit_test CASCADE")
        conn.execute("""
            CREATE TABLE limit_test (
                id SERIAL PRIMARY KEY,
                data TEXT
            )
        """)
        conn.execute("""
            INSERT INTO limit_test (data)
            SELECT md5(i::text)
            FROM generate_series(1, 100000) i
        """)
        conn.execute("ANALYZE limit_test")
        conn.close()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def test_limit_1(self):
        """Test LIMIT 1 cascades properly."""
        with self.harness.traced_session() as session:
            result = session.execute("SELECT * FROM limit_test LIMIT 1")
            self.assertEqual(len(result.rows), 1)

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            # All nodes must have matching END
            assert_all_nodes_paired(trace)

    def test_limit_10(self):
        """Test LIMIT 10 cascades properly."""
        with self.harness.traced_session() as session:
            result = session.execute("SELECT * FROM limit_test ORDER BY id LIMIT 10")
            self.assertEqual(len(result.rows), 10)

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            assert_all_nodes_paired(trace)

    def test_limit_with_offset(self):
        """Test LIMIT with OFFSET."""
        with self.harness.traced_session() as session:
            result = session.execute(
                "SELECT * FROM limit_test ORDER BY id LIMIT 10 OFFSET 100"
            )
            self.assertEqual(len(result.rows), 10)

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            assert_all_nodes_paired(trace)

    def test_limit_zero_rows(self):
        """Test LIMIT 0 (no rows returned)."""
        with self.harness.traced_session() as session:
            result = session.execute("SELECT * FROM limit_test LIMIT 0")
            self.assertEqual(len(result.rows), 0)

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            assert_all_nodes_paired(trace)

    def test_limit_on_join(self):
        """Test LIMIT on joined tables."""
        with self.harness.traced_session() as session:
            session.execute("""
                SELECT a.id, b.id
                FROM limit_test a
                CROSS JOIN limit_test b
                LIMIT 10
            """)

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            # Critical: cross join with limit must properly cascade
            assert_all_nodes_paired(trace)


class TestComplexPlans(unittest.TestCase):
    """Test complex query plans with many nodes."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

        conn = cls.harness.new_connection()

        # Create complex schema
        conn.execute("DROP TABLE IF EXISTS order_items CASCADE")
        conn.execute("DROP TABLE IF EXISTS complex_orders CASCADE")
        conn.execute("DROP TABLE IF EXISTS complex_products CASCADE")
        conn.execute("DROP TABLE IF EXISTS complex_customers CASCADE")
        conn.execute("DROP TABLE IF EXISTS categories CASCADE")

        conn.execute("""
            CREATE TABLE categories (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE complex_customers (
                id SERIAL PRIMARY KEY,
                name TEXT,
                email TEXT,
                created_at TIMESTAMP DEFAULT now()
            )
        """)
        conn.execute("""
            CREATE TABLE complex_products (
                id SERIAL PRIMARY KEY,
                name TEXT,
                category_id INTEGER REFERENCES categories(id),
                price NUMERIC(10,2)
            )
        """)
        conn.execute("""
            CREATE TABLE complex_orders (
                id SERIAL PRIMARY KEY,
                customer_id INTEGER REFERENCES complex_customers(id),
                total NUMERIC(10,2),
                status TEXT,
                order_date DATE
            )
        """)
        conn.execute("""
            CREATE TABLE order_items (
                id SERIAL PRIMARY KEY,
                order_id INTEGER REFERENCES complex_orders(id),
                product_id INTEGER REFERENCES complex_products(id),
                quantity INTEGER,
                unit_price NUMERIC(10,2)
            )
        """)

        # Insert data
        conn.execute("INSERT INTO categories (name) SELECT 'Category_' || i FROM generate_series(1, 20) i")
        conn.execute("INSERT INTO complex_customers (name, email) SELECT 'Cust_' || i, 'cust' || i || '@test.com' FROM generate_series(1, 500) i")
        conn.execute("INSERT INTO complex_products (name, category_id, price) SELECT 'Prod_' || i, (i % 20) + 1, (i * 1.5)::numeric(10,2) FROM generate_series(1, 200) i")
        conn.execute("INSERT INTO complex_orders (customer_id, total, status, order_date) SELECT (i % 500) + 1, (i * 10)::numeric(10,2), CASE i % 3 WHEN 0 THEN 'complete' WHEN 1 THEN 'pending' ELSE 'cancelled' END, CURRENT_DATE - (i % 365) FROM generate_series(1, 5000) i")
        conn.execute("INSERT INTO order_items (order_id, product_id, quantity, unit_price) SELECT (i % 5000) + 1, (i % 200) + 1, (i % 5) + 1, ((i % 200) * 1.5)::numeric(10,2) FROM generate_series(1, 20000) i")

        conn.execute("ANALYZE categories")
        conn.execute("ANALYZE complex_customers")
        conn.execute("ANALYZE complex_products")
        conn.execute("ANALYZE complex_orders")
        conn.execute("ANALYZE order_items")
        conn.close()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def test_five_table_join(self):
        """Test 5-table join with aggregation."""
        with self.harness.traced_session() as session:
            session.execute("""
                SELECT
                    cat.name as category,
                    COUNT(DISTINCT o.id) as order_count,
                    SUM(oi.quantity * oi.unit_price) as total_revenue
                FROM categories cat
                JOIN complex_products p ON p.category_id = cat.id
                JOIN order_items oi ON oi.product_id = p.id
                JOIN complex_orders o ON o.id = oi.order_id
                JOIN complex_customers c ON c.id = o.customer_id
                WHERE o.status = 'complete'
                GROUP BY cat.name
                ORDER BY total_revenue DESC
            """)

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            # Must have many nodes (5 scans + 4 joins + agg + sort + at least)
            self.assertGreaterEqual(len(trace.node_starts), 8)

            assert_all_nodes_paired(trace)
            assert_node_timing_valid(trace)

    def test_window_function(self):
        """Test window function node tracking."""
        with self.harness.traced_session() as session:
            session.execute("""
                SELECT
                    customer_id,
                    total,
                    SUM(total) OVER (PARTITION BY customer_id ORDER BY order_date) as running_total,
                    ROW_NUMBER() OVER (PARTITION BY customer_id ORDER BY order_date) as order_num
                FROM complex_orders
                WHERE customer_id <= 10
                ORDER BY customer_id, order_date
            """)

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            assert_all_nodes_paired(trace)

    def test_recursive_cte(self):
        """Test recursive CTE node tracking."""
        with self.harness.traced_session() as session:
            session.execute("""
                WITH RECURSIVE numbers AS (
                    SELECT 1 as n
                    UNION ALL
                    SELECT n + 1 FROM numbers WHERE n < 100
                )
                SELECT SUM(n) FROM numbers
            """)

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            assert_all_nodes_paired(trace)

    def test_lateral_join(self):
        """Test LATERAL join node tracking."""
        with self.harness.traced_session() as session:
            session.execute("""
                SELECT c.name, latest.total
                FROM complex_customers c
                CROSS JOIN LATERAL (
                    SELECT total
                    FROM complex_orders o
                    WHERE o.customer_id = c.id
                    ORDER BY order_date DESC
                    LIMIT 1
                ) latest
                WHERE c.id <= 50
            """)

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            assert_all_nodes_paired(trace)


class TestNodeTiming(unittest.TestCase):
    """Test node timing correctness."""

    @classmethod
    def setUpClass(cls):
        cls.harness = PgHarness()

    @classmethod
    def tearDownClass(cls):
        cls.harness.cleanup()

    def test_node_end_after_start(self):
        """Verify all NODE_END timestamps are after NODE_START."""
        with self.harness.traced_session() as session:
            session.execute("SELECT * FROM generate_series(1, 10000) ORDER BY 1")

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            # This assertion checks end >= start for all nodes
            assert_node_timing_valid(trace)

    def test_child_within_parent(self):
        """Verify child node execution is within parent time bounds."""
        with self.harness.traced_session() as session:
            # Query with nested nodes
            session.execute("""
                SELECT * FROM (
                    SELECT * FROM generate_series(1, 100) s1
                ) sub
                ORDER BY s1
            """)

            trace_info = session.get_trace()
            trace = parse_trace(trace_info.path)

            # Basic timing validation
            assert_node_timing_valid(trace)
            assert_all_nodes_paired(trace)


if __name__ == '__main__':
    unittest.main(verbosity=2)
