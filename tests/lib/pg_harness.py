#!/usr/bin/env python3
"""
PostgreSQL Test Harness - Run queries and collect traces.

This module provides infrastructure for:
1. Connecting to PostgreSQL
2. Enabling/disabling tracing on backends
3. Running queries and collecting trace files
4. Comparing traces against EXPLAIN ANALYZE output
5. Cross-backend testing

Usage:
    harness = PgHarness()
    with harness.traced_session() as session:
        session.execute("SELECT * FROM test_table")
        trace = session.get_trace()
        result = validate_trace(trace.path)
"""

import os
import time
import glob
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
from pathlib import Path

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False


@dataclass
class PgConfig:
    """PostgreSQL connection configuration."""
    host: str = "localhost"
    port: int = 5432
    dbname: str = "postgres"
    user: str = "postgres"
    password: str = ""
    trace_dir: str = "/tmp"

    @classmethod
    def from_env(cls) -> 'PgConfig':
        """Create config from environment variables."""
        return cls(
            host=os.environ.get('PGHOST', 'localhost'),
            port=int(os.environ.get('PGPORT', '5432')),
            dbname=os.environ.get('PGDATABASE', 'postgres'),
            user=os.environ.get('PGUSER', 'postgres'),
            password=os.environ.get('PGPASSWORD', ''),
            trace_dir=os.environ.get('PG10046_TRACE_DIR', '/tmp'),
        )

    def connection_string(self) -> str:
        """Return psycopg2 connection string."""
        parts = [f"host={self.host}", f"port={self.port}", f"dbname={self.dbname}", f"user={self.user}"]
        if self.password:
            parts.append(f"password={self.password}")
        return " ".join(parts)


@dataclass
class QueryResult:
    """Result of executing a query."""
    sql: str
    rows: List[Dict] = field(default_factory=list)
    rowcount: int = 0
    duration_ms: float = 0
    error: Optional[str] = None


@dataclass
class ExplainPlan:
    """Parsed EXPLAIN ANALYZE output."""
    sql: str
    plan_text: str
    nodes: List[Dict] = field(default_factory=list)
    total_time_ms: float = 0
    planning_time_ms: float = 0
    execution_time_ms: float = 0


@dataclass
class TraceInfo:
    """Information about a collected trace file."""
    path: str
    pid: int
    trace_id: str
    size_bytes: int = 0
    exists: bool = False


class PgConnection:
    """Wrapper around psycopg2 connection with tracing support."""

    def __init__(self, config: PgConfig):
        self.config = config
        self.conn = None
        self.pid: Optional[int] = None
        self._trace_enabled = False
        self._trace_start_time: Optional[float] = None
        self._closed = False

    def connect(self):
        """Establish connection to PostgreSQL."""
        if not HAS_PSYCOPG2:
            raise RuntimeError("psycopg2 not installed. Run: pip install psycopg2-binary")

        self.conn = psycopg2.connect(self.config.connection_string())
        self.conn.autocommit = True

        # Get our backend PID
        with self.conn.cursor() as cur:
            cur.execute("SELECT pg_backend_pid()")
            self.pid = cur.fetchone()[0]

    def close(self):
        """Close the connection."""
        if self.conn:
            self.conn.close()
            self.conn = None
            self.pid = None
        self._closed = True

    def execute(self, sql: str, params: tuple = None) -> QueryResult:
        """Execute a query and return results."""
        result = QueryResult(sql=sql)
        start = time.time()

        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(sql, params)
                result.rowcount = cur.rowcount

                if cur.description:  # SELECT query
                    result.rows = [dict(row) for row in cur.fetchall()]

        except Exception as e:
            result.error = str(e)

        result.duration_ms = (time.time() - start) * 1000
        return result

    def explain_analyze(self, sql: str, params: tuple = None) -> ExplainPlan:
        """Run EXPLAIN ANALYZE and parse the output."""
        explain_sql = f"EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) {sql}"

        with self.conn.cursor() as cur:
            cur.execute(explain_sql, params)
            plan_lines = [row[0] for row in cur.fetchall()]

        plan = ExplainPlan(sql=sql, plan_text="\n".join(plan_lines))
        self._parse_explain_output(plan, plan_lines)
        return plan

    def _parse_explain_output(self, plan: ExplainPlan, lines: List[str]):
        """Parse EXPLAIN ANALYZE output into structured data."""
        import re

        node_pattern = re.compile(
            r'^(\s*)->\s*(\w+(?:\s+\w+)*)\s+.*'
            r'actual time=([\d.]+)\.\.([\d.]+)\s+rows=(\d+)\s+loops=(\d+)'
        )
        timing_pattern = re.compile(r'(Planning|Execution) Time: ([\d.]+) ms')

        for line in lines:
            # Parse timing
            match = timing_pattern.search(line)
            if match:
                time_type, time_ms = match.groups()
                if time_type == "Planning":
                    plan.planning_time_ms = float(time_ms)
                else:
                    plan.execution_time_ms = float(time_ms)
                continue

            # Parse node
            match = node_pattern.match(line)
            if match:
                indent, node_type, start_time, end_time, rows, loops = match.groups()
                depth = len(indent) // 2 + 1
                plan.nodes.append({
                    'depth': depth,
                    'node_type': node_type.replace(' ', ''),
                    'actual_start_ms': float(start_time),
                    'actual_end_ms': float(end_time),
                    'actual_rows': int(rows),
                    'loops': int(loops),
                })

        plan.total_time_ms = plan.planning_time_ms + plan.execution_time_ms


class TracedSession:
    """A session with tracing enabled."""

    def __init__(self, conn: PgConnection, control_conn: PgConnection, config: PgConfig):
        self.conn = conn
        self.control_conn = control_conn
        self.config = config
        self._trace_info: Optional[TraceInfo] = None
        self._queries_executed: List[QueryResult] = []
        self._explains: List[ExplainPlan] = []
        self._saved_pid: Optional[int] = None  # Saved PID for after connection close

    def enable_trace(self, ebpf_active: bool = False):
        """Enable tracing on this session from the control connection."""
        # Save PID immediately when enabling trace
        if self._saved_pid is None and self.conn.pid:
            self._saved_pid = self.conn.pid

        func = "enable_trace_ebpf" if ebpf_active else "enable_trace"
        result = self.control_conn.execute(
            f"SELECT trace_10046.{func}(%s)",
            (self.conn.pid,)
        )
        if result.error:
            raise RuntimeError(f"Failed to enable trace: {result.error}")

    def disable_trace(self):
        """Disable tracing request."""
        self.control_conn.execute(
            "SELECT trace_10046.disable_trace(%s)",
            (self.conn.pid,)
        )

    def execute(self, sql: str, params: tuple = None, with_explain: bool = True) -> QueryResult:
        """Execute a query (tracing should capture it)."""
        # Save PID before any operations (in case connection closes later)
        if self._saved_pid is None and self.conn.pid:
            self._saved_pid = self.conn.pid
        result = self.conn.execute(sql, params)
        self._queries_executed.append(result)

        if with_explain and not result.error:
            try:
                explain = self.conn.explain_analyze(sql, params)
                self._explains.append(explain)
            except Exception:
                pass  # Some queries can't be explained

        return result

    def execute_many(self, queries: List[str]) -> List[QueryResult]:
        """Execute multiple queries."""
        return [self.execute(sql) for sql in queries]

    def wait_for_trace(self, timeout_sec: float = 10.0) -> Optional[TraceInfo]:
        """Wait for trace file to appear and return its info."""
        # Use saved PID if connection is closed
        pid = self._saved_pid or self.conn.pid
        if not pid:
            return None

        pattern = f"{self.config.trace_dir}/pg_10046_{pid}_*.trc"
        start = time.time()

        while time.time() - start < timeout_sec:
            files = glob.glob(pattern)
            if files:
                # Get the most recent file
                latest = max(files, key=os.path.getmtime)
                self._trace_info = TraceInfo(
                    path=latest,
                    pid=pid,
                    trace_id=Path(latest).stem,
                    size_bytes=os.path.getsize(latest),
                    exists=True
                )
                return self._trace_info
            time.sleep(0.1)

        return None

    def get_trace(self) -> Optional[TraceInfo]:
        """Get trace file info (waits if necessary).

        NOTE: With async buffering, trace data is flushed when the connection
        closes. This method closes the connection to ensure data is flushed
        before reading the trace file.
        """
        # Close connection to trigger buffer flush (async buffering)
        if self.conn and not self.conn._closed:
            self.conn.close()
            self.conn._closed = True
            time.sleep(2.0)  # Give time for on_proc_exit to flush and worker to write

        if self._trace_info:
            # Re-read file size after flush
            if os.path.exists(self._trace_info.path):
                self._trace_info = TraceInfo(
                    path=self._trace_info.path,
                    pid=self._trace_info.pid,
                    trace_id=self._trace_info.trace_id,
                    size_bytes=os.path.getsize(self._trace_info.path),
                    exists=True
                )
            return self._trace_info
        return self.wait_for_trace()

    def get_queries(self) -> List[QueryResult]:
        """Get list of executed queries."""
        return self._queries_executed

    def get_explains(self) -> List[ExplainPlan]:
        """Get EXPLAIN ANALYZE results for executed queries."""
        return self._explains


class PgHarness:
    """Test harness for pg_10046 testing."""

    def __init__(self, config: PgConfig = None):
        self.config = config or PgConfig.from_env()
        self._connections: List[PgConnection] = []

    def new_connection(self) -> PgConnection:
        """Create a new PostgreSQL connection."""
        conn = PgConnection(self.config)
        conn.connect()
        self._connections.append(conn)
        return conn

    def cleanup(self):
        """Close all connections."""
        for conn in self._connections:
            conn.close()
        self._connections = []

    def cleanup_traces(self, pattern: str = "pg_10046_*.trc"):
        """Remove trace files matching pattern."""
        for f in glob.glob(f"{self.config.trace_dir}/{pattern}"):
            try:
                os.remove(f)
            except OSError:
                pass

    @contextmanager
    def traced_session(self, cleanup: bool = True, ebpf_active: bool = False):
        """Context manager for a traced session.

        Creates two connections:
        - One for running queries (will be traced)
        - One for controlling trace (enable/disable)

        Usage:
            with harness.traced_session() as session:
                session.execute("SELECT 1")
                trace = session.get_trace()
        """
        if cleanup:
            self.cleanup_traces()

        # Create connections
        target_conn = self.new_connection()
        control_conn = self.new_connection()

        session = TracedSession(target_conn, control_conn, self.config)

        try:
            # Enable tracing
            session.enable_trace(ebpf_active=ebpf_active)

            yield session

        finally:
            # Only disable if connection is still open (get_trace may have closed it)
            if target_conn.pid:
                session.disable_trace()
            if not target_conn._closed:
                target_conn.close()
            control_conn.close()
            self._connections = [c for c in self._connections if c not in (target_conn, control_conn)]

    @contextmanager
    def multiple_sessions(self, count: int, cleanup: bool = True):
        """Create multiple traced sessions for concurrent testing."""
        if cleanup:
            self.cleanup_traces()

        control_conn = self.new_connection()
        sessions = []

        try:
            for _ in range(count):
                target_conn = self.new_connection()
                session = TracedSession(target_conn, control_conn, self.config)
                session.enable_trace()
                sessions.append(session)

            yield sessions

        finally:
            for session in sessions:
                session.disable_trace()
                session.conn.close()
            control_conn.close()

    def run_psql(self, sql: str, timeout: int = 30) -> Tuple[str, str, int]:
        """Run SQL via psql command (for cases where we need shell access)."""
        cmd = [
            "psql",
            "-h", self.config.host,
            "-p", str(self.config.port),
            "-U", self.config.user,
            "-d", self.config.dbname,
            "-c", sql,
            "-t", "-A"  # tuples only, unaligned
        ]

        env = os.environ.copy()
        if self.config.password:
            env['PGPASSWORD'] = self.config.password

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Timeout", -1


def compare_trace_to_explain(trace_path: str, explain: ExplainPlan) -> Dict[str, Any]:
    """Compare a trace file against EXPLAIN ANALYZE output.

    Returns a dict with comparison results:
    - nodes_match: bool - do plan node types match?
    - row_counts_match: bool - do actual row counts match?
    - timing_reasonable: bool - is trace timing within bounds of EXPLAIN timing?
    - differences: list of specific differences found
    """
    from .trace_validator import TraceParser

    parser = TraceParser(trace_path)
    trace = parser.parse()

    result = {
        'nodes_match': True,
        'row_counts_match': True,
        'timing_reasonable': True,
        'differences': []
    }

    # Find the query in trace that matches the explain's SQL
    matching_query = None
    for query in trace.queries:
        if query.sql.strip() == explain.sql.strip():
            matching_query = query
            break

    if not matching_query:
        result['differences'].append(f"Query not found in trace: {explain.sql[:50]}...")
        result['nodes_match'] = False
        return result

    # Compare plan nodes
    trace_nodes = matching_query.plan_nodes
    explain_nodes = explain.nodes

    if len(trace_nodes) != len(explain_nodes):
        result['nodes_match'] = False
        result['differences'].append(
            f"Node count mismatch: trace={len(trace_nodes)}, explain={len(explain_nodes)}"
        )

    # Compare node types (accounting for naming differences)
    for i, (tn, en) in enumerate(zip(trace_nodes, explain_nodes)):
        trace_type = tn.get('node_type', '').replace(' ', '')
        explain_type = en.get('node_type', '').replace(' ', '')

        if trace_type != explain_type:
            result['nodes_match'] = False
            result['differences'].append(
                f"Node {i+1} type mismatch: trace={trace_type}, explain={explain_type}"
            )

    # Compare row counts from stats
    for stat in matching_query.stats:
        node_id = stat.get('node_id', 0)
        trace_tuples = stat.get('tuples', 0)

        # Find corresponding explain node
        if node_id <= len(explain_nodes):
            explain_tuples = explain_nodes[node_id - 1].get('actual_rows', 0)
            if trace_tuples != explain_tuples:
                result['row_counts_match'] = False
                result['differences'].append(
                    f"Node {node_id} row count mismatch: trace={trace_tuples}, explain={explain_tuples}"
                )

    # Compare timing (allow 50% tolerance)
    if matching_query.elapsed_us:
        trace_ms = matching_query.elapsed_us / 1000
        explain_ms = explain.execution_time_ms

        if explain_ms > 0:
            ratio = trace_ms / explain_ms
            if ratio < 0.5 or ratio > 2.0:
                result['timing_reasonable'] = False
                result['differences'].append(
                    f"Timing mismatch: trace={trace_ms:.2f}ms, explain={explain_ms:.2f}ms (ratio={ratio:.2f})"
                )

    return result


if __name__ == "__main__":
    # Simple self-test
    print("Testing PgHarness...")

    harness = PgHarness()

    try:
        with harness.traced_session() as session:
            # Run a simple query
            result = session.execute("SELECT 1 as test")
            print(f"Query result: {result.rows}")

            # Wait for trace
            trace = session.get_trace()
            if trace:
                print(f"Trace file: {trace.path}")
                print(f"Trace size: {trace.size_bytes} bytes")
            else:
                print("No trace file found")

    except Exception as e:
        print(f"Error: {e}")

    finally:
        harness.cleanup()
