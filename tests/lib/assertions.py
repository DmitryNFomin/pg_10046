#!/usr/bin/env python3
"""
Test Assertions - Reusable correctness checks for pg_10046 traces.

This module provides assertion functions that can be used across all tests
to verify trace correctness. Each assertion raises AssertionError with
detailed context on failure.

Usage:
    from lib.assertions import *

    trace = parse_trace("trace.trc")
    assert_header_present(trace)
    assert_all_nodes_paired(trace)
    assert_query_count(trace, expected=3)
"""

from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass

from .trace_validator import (
    TraceFile, TraceEvent, EventType, ValidationResult,
    TraceParser, TraceValidator, QueryExecution
)


class TraceAssertionError(AssertionError):
    """Assertion error with trace context."""

    def __init__(self, message: str, trace_path: str = None, details: List[str] = None):
        self.trace_path = trace_path
        self.details = details or []
        full_message = message
        if trace_path:
            full_message = f"{message}\n  Trace: {trace_path}"
        if details:
            full_message += "\n  Details:\n    " + "\n    ".join(details)
        super().__init__(full_message)


def parse_trace(path: str) -> TraceFile:
    """Parse a trace file and return structured data."""
    parser = TraceParser(path)
    return parser.parse()


def validate_trace(path: str) -> ValidationResult:
    """Validate a trace file and return result."""
    validator = TraceValidator(path)
    return validator.validate()


# ============================================================================
# Header Assertions
# ============================================================================

def assert_header_present(trace: TraceFile, required_fields: List[str] = None):
    """Assert trace has a valid header with required fields."""
    if required_fields is None:
        required_fields = ['TRACE_ID', 'PID', 'START_TIME']

    if not trace.header:
        raise TraceAssertionError(
            "Trace file has no header",
            trace.path
        )

    missing = [f for f in required_fields if f not in trace.header]
    if missing:
        raise TraceAssertionError(
            f"Missing required header fields: {missing}",
            trace.path,
            [f"Present fields: {list(trace.header.keys())}"]
        )


def assert_header_value(trace: TraceFile, field: str, expected: str):
    """Assert a specific header field has expected value."""
    actual = trace.header.get(field)
    if actual != expected:
        raise TraceAssertionError(
            f"Header field '{field}' mismatch",
            trace.path,
            [f"Expected: {expected}", f"Actual: {actual}"]
        )


# ============================================================================
# Query Assertions
# ============================================================================

def assert_query_count(trace: TraceFile, expected: int, message: str = None):
    """Assert trace contains expected number of queries."""
    actual = len(trace.queries)
    if actual != expected:
        raise TraceAssertionError(
            message or f"Query count mismatch: expected {expected}, got {actual}",
            trace.path,
            [f"Queries found: {[q.sql[:50] for q in trace.queries]}"]
        )


def assert_query_count_at_least(trace: TraceFile, minimum: int):
    """Assert trace contains at least minimum number of queries."""
    actual = len(trace.queries)
    if actual < minimum:
        raise TraceAssertionError(
            f"Expected at least {minimum} queries, got {actual}",
            trace.path
        )


def assert_query_captured(trace: TraceFile, sql_pattern: str):
    """Assert a query matching the pattern was captured."""
    import re
    pattern = re.compile(sql_pattern, re.IGNORECASE)

    for query in trace.queries:
        if pattern.search(query.sql):
            return query

    raise TraceAssertionError(
        f"No query matching pattern '{sql_pattern}' found",
        trace.path,
        [f"Queries: {[q.sql[:50] for q in trace.queries]}"]
    )


def assert_query_complete(query: QueryExecution, trace_path: str = None):
    """Assert a query has all required components."""
    issues = []

    if not query.sql:
        issues.append("Missing SQL text")
    if not query.plan_nodes:
        issues.append("Missing plan nodes")
    if query.end_time is None:
        issues.append("Missing EXEC_END (query incomplete)")
    if not query.stats:
        issues.append("Missing execution statistics")

    if issues:
        raise TraceAssertionError(
            f"Query {query.query_id} is incomplete",
            trace_path,
            issues
        )


def assert_all_queries_complete(trace: TraceFile):
    """Assert all queries in trace are complete."""
    for query in trace.queries:
        assert_query_complete(query, trace.path)


# ============================================================================
# Node Assertions
# ============================================================================

def assert_all_nodes_paired(trace: TraceFile):
    """Assert every NODE_START has a matching NODE_END."""
    unmatched = []

    for ptr, starts in trace.node_starts.items():
        ends = trace.node_ends.get(ptr, [])

        if len(starts) != len(ends):
            unmatched.append(f"{ptr}: {len(starts)} starts, {len(ends)} ends")

    if unmatched:
        raise TraceAssertionError(
            "Unmatched NODE_START/NODE_END pairs",
            trace.path,
            unmatched
        )


def assert_node_count(trace: TraceFile, expected: int):
    """Assert trace has expected number of unique nodes."""
    actual = len(trace.node_starts)
    if actual != expected:
        raise TraceAssertionError(
            f"Node count mismatch: expected {expected}, got {actual}",
            trace.path
        )


def assert_node_types_present(trace: TraceFile, expected_types: List[str]):
    """Assert specific node types are present in trace."""
    present_types: Set[str] = set()

    for events in trace.node_starts.values():
        for event in events:
            present_types.add(event.data.get('node_type', ''))

    missing = set(expected_types) - present_types
    if missing:
        raise TraceAssertionError(
            f"Expected node types not found: {missing}",
            trace.path,
            [f"Present types: {present_types}"]
        )


def assert_node_timing_valid(trace: TraceFile):
    """Assert all node timings are valid (end >= start)."""
    invalid = []

    for ptr, starts in trace.node_starts.items():
        ends = trace.node_ends.get(ptr, [])

        for start, end in zip(starts, ends):
            if start.timestamp and end.timestamp:
                if end.timestamp < start.timestamp:
                    invalid.append(
                        f"{ptr}: end ({end.timestamp}) < start ({start.timestamp})"
                    )

    if invalid:
        raise TraceAssertionError(
            "Invalid node timings detected",
            trace.path,
            invalid
        )


# ============================================================================
# Event Ordering Assertions
# ============================================================================

def assert_event_order(trace: TraceFile, expected_order: List[EventType]):
    """Assert events appear in expected order (not necessarily consecutive)."""
    actual_order = [e.event_type for e in trace.events if e.event_type in expected_order]

    # Check that expected_order is a subsequence of actual_order
    expected_idx = 0
    for event_type in actual_order:
        if event_type == expected_order[expected_idx]:
            expected_idx += 1
            if expected_idx >= len(expected_order):
                return  # All expected events found in order

    raise TraceAssertionError(
        "Events not in expected order",
        trace.path,
        [
            f"Expected: {[e.name for e in expected_order]}",
            f"Found: {[e.name for e in actual_order[:20]]}..."
        ]
    )


def assert_header_before_events(trace: TraceFile):
    """Assert header comments come before other events."""
    seen_non_header = False
    header_after_events = []

    for event in trace.events:
        if event.event_type == EventType.HEADER:
            if seen_non_header:
                header_after_events.append(f"Line {event.line_num}: {event.raw_line[:50]}")
        elif event.event_type != EventType.UNKNOWN:
            seen_non_header = True

    if header_after_events:
        raise TraceAssertionError(
            "Header lines found after non-header events",
            trace.path,
            header_after_events
        )


# ============================================================================
# Statistics Assertions
# ============================================================================

def assert_stats_present(trace: TraceFile):
    """Assert execution statistics are present for all queries."""
    queries_without_stats = []

    for query in trace.queries:
        if not query.stats:
            queries_without_stats.append(f"Query {query.query_id}: {query.sql[:30]}...")

    if queries_without_stats:
        raise TraceAssertionError(
            "Queries missing execution statistics",
            trace.path,
            queries_without_stats
        )


def assert_tuple_count(trace: TraceFile, query_id: int, node_id: int, expected: int):
    """Assert a specific node has expected tuple count."""
    for query in trace.queries:
        if query.query_id == query_id:
            for stat in query.stats:
                if stat.get('node_id') == node_id:
                    actual = stat.get('tuples', 0)
                    if actual != expected:
                        raise TraceAssertionError(
                            f"Tuple count mismatch for query {query_id}, node {node_id}",
                            trace.path,
                            [f"Expected: {expected}", f"Actual: {actual}"]
                        )
                    return

    raise TraceAssertionError(
        f"Node {node_id} not found in query {query_id} stats",
        trace.path
    )


def assert_buffer_stats_reasonable(trace: TraceFile):
    """Assert buffer statistics are reasonable (non-negative, etc.)."""
    issues = []

    for query in trace.queries:
        for stat in query.stats:
            node_id = stat.get('node_id', 0)
            blks_hit = stat.get('blks_hit', 0)
            blks_read = stat.get('blks_read', 0)

            if blks_hit < 0:
                issues.append(f"Query {query.query_id}, Node {node_id}: negative blks_hit ({blks_hit})")
            if blks_read < 0:
                issues.append(f"Query {query.query_id}, Node {node_id}: negative blks_read ({blks_read})")

    if issues:
        raise TraceAssertionError(
            "Invalid buffer statistics",
            trace.path,
            issues
        )


# ============================================================================
# Comparison Assertions
# ============================================================================

def assert_trace_matches_explain(trace: TraceFile, explain_nodes: List[Dict], query_id: int = 1):
    """Assert trace plan matches EXPLAIN ANALYZE output."""
    query = None
    for q in trace.queries:
        if q.query_id == query_id:
            query = q
            break

    if not query:
        raise TraceAssertionError(
            f"Query {query_id} not found in trace",
            trace.path
        )

    trace_types = [n.get('node_type', '') for n in query.plan_nodes]
    explain_types = [n.get('node_type', '') for n in explain_nodes]

    if len(trace_types) != len(explain_types):
        raise TraceAssertionError(
            f"Plan node count mismatch",
            trace.path,
            [f"Trace nodes: {len(trace_types)}", f"Explain nodes: {len(explain_types)}"]
        )

    mismatches = []
    for i, (t, e) in enumerate(zip(trace_types, explain_types)):
        if t != e:
            mismatches.append(f"Node {i+1}: trace={t}, explain={e}")

    if mismatches:
        raise TraceAssertionError(
            "Plan structure mismatch",
            trace.path,
            mismatches
        )


def assert_row_counts_match(trace: TraceFile, expected_counts: Dict[int, int], query_id: int = 1):
    """Assert row counts match expected values.

    Args:
        trace: Parsed trace file
        expected_counts: Dict mapping node_id -> expected row count
        query_id: Which query to check (default 1)
    """
    query = None
    for q in trace.queries:
        if q.query_id == query_id:
            query = q
            break

    if not query:
        raise TraceAssertionError(f"Query {query_id} not found", trace.path)

    mismatches = []
    for stat in query.stats:
        node_id = stat.get('node_id', 0)
        if node_id in expected_counts:
            expected = expected_counts[node_id]
            actual = stat.get('tuples', 0)
            if actual != expected:
                mismatches.append(f"Node {node_id}: expected {expected}, got {actual}")

    if mismatches:
        raise TraceAssertionError(
            "Row count mismatches",
            trace.path,
            mismatches
        )


# ============================================================================
# Validation Wrapper
# ============================================================================

def assert_trace_valid(path: str, allow_warnings: bool = True):
    """Assert trace file passes all validation checks."""
    result = validate_trace(path)

    if not result.is_valid:
        raise TraceAssertionError(
            "Trace validation failed",
            path,
            [f"[{e.error_type}] {e.message}" for e in result.errors]
        )

    if not allow_warnings and result.warnings:
        raise TraceAssertionError(
            "Trace has warnings",
            path,
            [f"[{w.error_type}] {w.message}" for w in result.warnings]
        )

    return result


# ============================================================================
# Composite Assertions
# ============================================================================

def assert_trace_complete_and_valid(trace: TraceFile):
    """Run all standard assertions on a trace."""
    assert_header_present(trace)
    assert_header_before_events(trace)
    assert_all_nodes_paired(trace)
    assert_node_timing_valid(trace)
    assert_all_queries_complete(trace)
    assert_stats_present(trace)
    assert_buffer_stats_reasonable(trace)


def assert_basic_trace_correctness(path: str) -> TraceFile:
    """Assert basic trace correctness and return parsed trace.

    This is the standard check to run on every test.
    """
    # Validate first
    result = validate_trace(path)
    if not result.is_valid:
        raise TraceAssertionError(
            "Trace validation failed",
            path,
            [f"[{e.error_type}] {e.message}" for e in result.errors]
        )

    # Parse and run assertions
    trace = parse_trace(path)
    assert_trace_complete_and_valid(trace)

    return trace
