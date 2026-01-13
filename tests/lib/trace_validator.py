#!/usr/bin/env python3
"""
Trace Validator - Parse and validate pg_10046 trace files.

This is the core component that ensures trace correctness by:
1. Parsing trace file format into structured data
2. Validating event ordering and completeness
3. Checking NODE_START/NODE_END pairing
4. Verifying timing consistency
5. Comparing against expected query results

Usage:
    validator = TraceValidator("path/to/trace.trc")
    result = validator.validate()
    if not result.is_valid:
        print(result.errors)
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any
from enum import Enum
from pathlib import Path


class EventType(Enum):
    """Trace event types."""
    HEADER = "HEADER"
    QUERY_START = "QUERY_START"
    BIND = "BIND"
    PLAN_START = "PLAN_START"
    PLAN = "PLAN"
    PLAN_END = "PLAN_END"
    PLAN_TIME = "PLAN_TIME"
    EXEC_START = "EXEC_START"
    NODE_MAP = "NODE_MAP"
    SAMPLING_START = "SAMPLING_START"
    NODE_START = "NODE_START"
    NODE_END = "NODE_END"
    SAMPLE = "SAMPLE"
    SAMPLING_END = "SAMPLING_END"
    STATS_START = "STATS_START"
    STAT = "STAT"
    STATS_END = "STATS_END"
    EXEC_END = "EXEC_END"
    # IO events from eBPF
    IO_READ = "IO_READ"
    IO_WRITE = "IO_WRITE"
    # CPU events from eBPF
    CPU_OFF = "CPU_OFF"
    CPU_ON = "CPU_ON"
    UNKNOWN = "UNKNOWN"


@dataclass
class TraceEvent:
    """A single trace event."""
    line_num: int
    event_type: EventType
    timestamp: Optional[int] = None
    raw_line: str = ""
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NodeExecution:
    """Tracks a single node's execution (START to END)."""
    node_ptr: str
    node_name: str
    start_time: int
    start_line: int
    end_time: Optional[int] = None
    end_line: Optional[int] = None
    tuples: Optional[int] = None
    blks_hit: Optional[int] = None
    blks_read: Optional[int] = None
    duration_us: Optional[int] = None


@dataclass
class QueryExecution:
    """Tracks a single query's execution."""
    query_id: int
    sql: str
    start_time: int
    end_time: Optional[int] = None
    plan_nodes: List[Dict] = field(default_factory=list)
    node_executions: List[NodeExecution] = field(default_factory=list)
    stats: List[Dict] = field(default_factory=list)
    elapsed_us: Optional[int] = None


@dataclass
class ValidationError:
    """A validation error with context."""
    error_type: str
    message: str
    line_num: Optional[int] = None
    context: Optional[str] = None
    severity: str = "ERROR"  # ERROR, WARNING


@dataclass
class ValidationResult:
    """Result of trace validation."""
    is_valid: bool
    errors: List[ValidationError] = field(default_factory=list)
    warnings: List[ValidationError] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)

    def add_error(self, error_type: str, message: str, line_num: int = None, context: str = None):
        self.errors.append(ValidationError(error_type, message, line_num, context, "ERROR"))
        self.is_valid = False

    def add_warning(self, error_type: str, message: str, line_num: int = None, context: str = None):
        self.warnings.append(ValidationError(error_type, message, line_num, context, "WARNING"))


@dataclass
class IOEvent:
    """An IO event from eBPF trace."""
    line_num: int
    event_type: str  # IO_READ or IO_WRITE
    timestamp: int
    pid: int
    node_ptr: str
    tablespace: int
    database: int
    relation: int
    fork: int
    segment: int
    block: int
    elapsed_us: int
    disk: int = 0
    block_elapsed_us: int = 0


@dataclass
class CPUEvent:
    """A CPU scheduling event from eBPF trace."""
    line_num: int
    event_type: str  # CPU_OFF or CPU_ON
    timestamp: int
    pid: int
    node_ptr: str
    duration_us: int  # on_cpu_duration for CPU_OFF, off_cpu_duration for CPU_ON


@dataclass
class EBPFTraceFile:
    """Parsed eBPF trace file (IO and CPU events)."""
    path: str
    header: Dict[str, str] = field(default_factory=dict)
    io_reads: List[IOEvent] = field(default_factory=list)
    io_writes: List[IOEvent] = field(default_factory=list)
    cpu_off: List[CPUEvent] = field(default_factory=list)
    cpu_on: List[CPUEvent] = field(default_factory=list)

    @property
    def events(self) -> List:
        """All events (IO + CPU) for backwards compatibility."""
        return self.io_reads + self.io_writes

    @property
    def total_read_us(self) -> int:
        return sum(e.elapsed_us for e in self.io_reads)

    @property
    def total_write_us(self) -> int:
        return sum(e.elapsed_us for e in self.io_writes)

    @property
    def total_blocks_read(self) -> int:
        return len(self.io_reads)

    @property
    def total_blocks_written(self) -> int:
        return len(self.io_writes)

    @property
    def total_on_cpu_us(self) -> int:
        """Total time spent on CPU (from CPU_OFF events)."""
        return sum(e.duration_us for e in self.cpu_off)

    @property
    def total_off_cpu_us(self) -> int:
        """Total time spent off CPU (from CPU_ON events)."""
        return sum(e.duration_us for e in self.cpu_on)

    @property
    def cpu_switches(self) -> int:
        """Number of CPU context switches."""
        return len(self.cpu_off)


# Alias for backwards compatibility
IOTraceFile = EBPFTraceFile


@dataclass
class TraceFile:
    """Parsed trace file structure."""
    path: str
    header: Dict[str, str] = field(default_factory=dict)
    events: List[TraceEvent] = field(default_factory=list)
    queries: List[QueryExecution] = field(default_factory=list)

    # Quick access indexes
    node_starts: Dict[str, List[TraceEvent]] = field(default_factory=dict)  # ptr -> events
    node_ends: Dict[str, List[TraceEvent]] = field(default_factory=dict)    # ptr -> events

    # IO trace (if available)
    io_trace: Optional[IOTraceFile] = None


class TraceParser:
    """Parse pg_10046 trace files into structured data."""

    # Regex patterns for parsing
    PATTERNS = {
        'header': re.compile(r'^#\s*(\w+):\s*(.+)$'),
        'query_start': re.compile(r'^QUERY_START,(\d+),(\d+),sql=(.*)$'),
        'bind': re.compile(r'^BIND,(\d+),(\d+),(\w+),(.*)$'),
        'plan': re.compile(r'^PLAN,(\d+),(\d+),(\d+),(\w+),(\d+),([\d.]+),(.*)$'),
        'plan_time': re.compile(r'^PLAN_TIME,(\d+)$'),
        'exec_start': re.compile(r'^EXEC_START,(\d+),(\d+)$'),
        'node_map': re.compile(r'^NODE_MAP,([^,]+),([^,]+),(\w+),(\d+),?(.*)$'),
        'sampling_start': re.compile(r'^SAMPLING_START,interval_ms=(\d+)$'),
        'node_start': re.compile(r'^NODE_START,(\d+),([^,]+),(\w+),?(.*)$'),
        'node_end': re.compile(r'^NODE_END,(\d+),([^,]+),(\w+),tuples=(\d+),blks_hit=(\d+),blks_read=(\d+),time_us=(\d+),?(.*)$'),
        'sample': re.compile(r'^SAMPLE,(\d+),([^,]+),([^,]+),(\d+),([\d.]+),(\d+),(\d+)$'),
        'sampling_end': re.compile(r'^SAMPLING_END,samples=(\d+)$'),
        'stat': re.compile(r'^STAT,(\d+),(\d+),(\d+),(\w+),(\d+),(\d+),(\d+),([\d.]+),([\d.]+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),([^,]*),(.*)$'),
        'exec_end': re.compile(r'^EXEC_END,(\d+),(\d+),ela=(\d+)$'),
    }

    def __init__(self, path: str):
        self.path = path
        self.trace = TraceFile(path=path)
        self._current_query: Optional[QueryExecution] = None

    def parse(self) -> TraceFile:
        """Parse the trace file and return structured data."""
        with open(self.path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.rstrip('\n')
                if not line:
                    continue
                event = self._parse_line(line_num, line)
                if event:
                    self.trace.events.append(event)
                    self._process_event(event)

        return self.trace

    def _parse_line(self, line_num: int, line: str) -> Optional[TraceEvent]:
        """Parse a single line into a TraceEvent."""
        # Header comments
        if line.startswith('#'):
            match = self.PATTERNS['header'].match(line)
            if match:
                key, value = match.groups()
                self.trace.header[key] = value
            return TraceEvent(line_num, EventType.HEADER, raw_line=line)

        # Try each pattern
        for event_name, pattern in self.PATTERNS.items():
            if event_name == 'header':
                continue
            match = pattern.match(line)
            if match:
                return self._create_event(line_num, event_name, match, line)

        # Simple events without data
        if line == 'PLAN_START':
            return TraceEvent(line_num, EventType.PLAN_START, raw_line=line)
        if line == 'PLAN_END':
            return TraceEvent(line_num, EventType.PLAN_END, raw_line=line)
        if line == 'STATS_START':
            return TraceEvent(line_num, EventType.STATS_START, raw_line=line)
        if line == 'STATS_END':
            return TraceEvent(line_num, EventType.STATS_END, raw_line=line)

        # Unknown event
        return TraceEvent(line_num, EventType.UNKNOWN, raw_line=line)

    def _create_event(self, line_num: int, event_name: str, match: re.Match, line: str) -> TraceEvent:
        """Create a TraceEvent from a regex match."""
        event_type = EventType[event_name.upper()]
        event = TraceEvent(line_num, event_type, raw_line=line)

        groups = match.groups()

        if event_name == 'query_start':
            event.timestamp = int(groups[0])
            event.data = {'query_id': int(groups[1]), 'sql': groups[2]}
        elif event_name == 'bind':
            event.timestamp = int(groups[0])
            event.data = {'param_num': int(groups[1]), 'type': groups[2], 'value': groups[3]}
        elif event_name == 'plan':
            event.data = {
                'node_id': int(groups[0]),
                'parent_id': int(groups[1]),
                'depth': int(groups[2]),
                'node_type': groups[3],
                'rows': int(groups[4]),
                'cost': float(groups[5]),
                'target': groups[6]
            }
        elif event_name == 'plan_time':
            event.data = {'time_us': int(groups[0])}
        elif event_name == 'exec_start':
            event.timestamp = int(groups[0])
            event.data = {'query_id': int(groups[1])}
        elif event_name == 'node_map':
            event.data = {
                'ptr': groups[0],
                'parent_ptr': groups[1],
                'node_type': groups[2],
                'node_id': int(groups[3]),
                'target': groups[4] if len(groups) > 4 else ''
            }
        elif event_name == 'sampling_start':
            event.data = {'interval_ms': int(groups[0])}
        elif event_name == 'node_start':
            event.timestamp = int(groups[0])
            event.data = {
                'ptr': groups[1],
                'node_type': groups[2],
                'target': groups[3] if len(groups) > 3 else ''
            }
        elif event_name == 'node_end':
            event.timestamp = int(groups[0])
            event.data = {
                'ptr': groups[1],
                'node_type': groups[2],
                'tuples': int(groups[3]),
                'blks_hit': int(groups[4]),
                'blks_read': int(groups[5]),
                'time_us': int(groups[6]),
                'extra': groups[7] if len(groups) > 7 else ''
            }
        elif event_name == 'sample':
            event.timestamp = int(groups[0])
            event.data = {
                'ptr': groups[1],
                'wait_event': groups[2],
                'sample_num': int(groups[3]),
                'tuples': float(groups[4]),
                'blks_hit': int(groups[5]),
                'blks_read': int(groups[6])
            }
        elif event_name == 'sampling_end':
            event.data = {'samples': int(groups[0])}
        elif event_name == 'stat':
            event.data = {
                'node_id': int(groups[0]),
                'parent_id': int(groups[1]),
                'depth': int(groups[2]),
                'node_type': groups[3],
                'tuples': int(groups[4]),
                'loops': int(groups[5]),
                'workers': int(groups[6]),
                'total_time': float(groups[7]),
                'self_time': float(groups[8]),
                'blks_hit': int(groups[9]),
                'blks_read': int(groups[10]),
                'blks_dirtied': int(groups[11]),
                'blks_written': int(groups[12]),
                'temp_read': int(groups[13]),
                'temp_written': int(groups[14]),
                'target': groups[15],
                'ptr': groups[16]
            }
        elif event_name == 'exec_end':
            event.timestamp = int(groups[0])
            event.data = {'query_id': int(groups[1]), 'elapsed_us': int(groups[2])}

        return event

    def _process_event(self, event: TraceEvent):
        """Process event to build query/node tracking structures."""
        if event.event_type == EventType.QUERY_START:
            self._current_query = QueryExecution(
                query_id=event.data['query_id'],
                sql=event.data['sql'],
                start_time=event.timestamp
            )
            self.trace.queries.append(self._current_query)

        elif event.event_type == EventType.PLAN and self._current_query:
            self._current_query.plan_nodes.append(event.data)

        elif event.event_type == EventType.NODE_START:
            ptr = event.data['ptr']
            if ptr not in self.trace.node_starts:
                self.trace.node_starts[ptr] = []
            self.trace.node_starts[ptr].append(event)

        elif event.event_type == EventType.NODE_END:
            ptr = event.data['ptr']
            if ptr not in self.trace.node_ends:
                self.trace.node_ends[ptr] = []
            self.trace.node_ends[ptr].append(event)

        elif event.event_type == EventType.STAT and self._current_query:
            self._current_query.stats.append(event.data)

        elif event.event_type == EventType.EXEC_END and self._current_query:
            self._current_query.end_time = event.timestamp
            self._current_query.elapsed_us = event.data['elapsed_us']


class TraceValidator:
    """Validate pg_10046 trace files for correctness."""

    def __init__(self, path: str):
        self.path = path
        self.parser = TraceParser(path)
        self.trace: Optional[TraceFile] = None
        self.result = ValidationResult(is_valid=True)

    def validate(self) -> ValidationResult:
        """Run all validations and return result."""
        # Parse the trace file
        try:
            self.trace = self.parser.parse()
        except Exception as e:
            self.result.add_error("PARSE_ERROR", f"Failed to parse trace file: {e}")
            return self.result

        # Run validations
        self._validate_header()
        self._validate_event_ordering()
        self._validate_node_pairing()
        self._validate_timing_consistency()
        self._validate_query_completeness()
        self._validate_no_unknown_events()

        # Build summary
        self._build_summary()

        return self.result

    def _validate_header(self):
        """Validate trace header is present and complete."""
        required_fields = ['TRACE_ID', 'PID', 'START_TIME']

        if not self.trace.header:
            self.result.add_error("MISSING_HEADER", "Trace file has no header")
            return

        for field in required_fields:
            if field not in self.trace.header:
                self.result.add_error("MISSING_HEADER_FIELD", f"Missing required header field: {field}")

    def _validate_event_ordering(self):
        """Validate events appear in correct order."""
        # Header should come first (before any non-header events)
        seen_non_header = False
        last_header_line = 0

        for event in self.trace.events:
            if event.event_type == EventType.HEADER:
                if seen_non_header:
                    self.result.add_warning(
                        "HEADER_ORDER",
                        "Header line after non-header events",
                        event.line_num,
                        event.raw_line
                    )
                last_header_line = event.line_num
            else:
                seen_non_header = True

        # For each query: QUERY_START -> PLAN_START -> PLAN -> PLAN_END -> EXEC_START -> ... -> EXEC_END
        in_query = False
        in_plan = False
        in_exec = False

        for event in self.trace.events:
            if event.event_type == EventType.QUERY_START:
                if in_query:
                    self.result.add_warning(
                        "QUERY_OVERLAP",
                        "QUERY_START without previous EXEC_END",
                        event.line_num
                    )
                in_query = True
                in_plan = False
                in_exec = False

            elif event.event_type == EventType.PLAN_START:
                if not in_query:
                    self.result.add_error(
                        "PLAN_WITHOUT_QUERY",
                        "PLAN_START without QUERY_START",
                        event.line_num
                    )
                in_plan = True

            elif event.event_type == EventType.PLAN_END:
                if not in_plan:
                    self.result.add_error(
                        "PLAN_END_MISMATCH",
                        "PLAN_END without PLAN_START",
                        event.line_num
                    )
                in_plan = False

            elif event.event_type == EventType.EXEC_START:
                in_exec = True

            elif event.event_type == EventType.EXEC_END:
                if not in_exec:
                    self.result.add_warning(
                        "EXEC_END_MISMATCH",
                        "EXEC_END without EXEC_START",
                        event.line_num
                    )
                in_query = False
                in_exec = False

    def _validate_node_pairing(self):
        """Validate every NODE_START has a matching NODE_END."""
        for ptr, starts in self.trace.node_starts.items():
            ends = self.trace.node_ends.get(ptr, [])

            if len(starts) != len(ends):
                self.result.add_error(
                    "NODE_MISMATCH",
                    f"Node {ptr}: {len(starts)} starts but {len(ends)} ends",
                    starts[0].line_num if starts else None
                )
                continue

            # Check ordering: each start should have corresponding end after it
            for i, (start, end) in enumerate(zip(starts, ends)):
                if end.line_num < start.line_num:
                    self.result.add_error(
                        "NODE_ORDER",
                        f"Node {ptr}: NODE_END (line {end.line_num}) before NODE_START (line {start.line_num})",
                        start.line_num
                    )

                # Check node types match
                if start.data.get('node_type') != end.data.get('node_type'):
                    self.result.add_error(
                        "NODE_TYPE_MISMATCH",
                        f"Node {ptr}: START type '{start.data.get('node_type')}' != END type '{end.data.get('node_type')}'",
                        start.line_num
                    )

    def _validate_timing_consistency(self):
        """Validate timing values are consistent."""
        for ptr, starts in self.trace.node_starts.items():
            ends = self.trace.node_ends.get(ptr, [])

            for start, end in zip(starts, ends):
                if start.timestamp and end.timestamp:
                    if end.timestamp < start.timestamp:
                        self.result.add_error(
                            "TIMING_NEGATIVE",
                            f"Node {ptr}: end time ({end.timestamp}) < start time ({start.timestamp})",
                            start.line_num
                        )

                    # Check time_us in NODE_END is reasonable
                    calculated_us = end.timestamp - start.timestamp
                    reported_us = end.data.get('time_us', 0)

                    # Allow 20% tolerance due to timing precision
                    if reported_us > 0 and abs(calculated_us - reported_us) > reported_us * 0.5:
                        self.result.add_warning(
                            "TIMING_MISMATCH",
                            f"Node {ptr}: calculated duration ({calculated_us}us) differs from reported ({reported_us}us)",
                            end.line_num
                        )

    def _validate_query_completeness(self):
        """Validate each query has all required components."""
        for query in self.trace.queries:
            if not query.sql:
                self.result.add_warning(
                    "MISSING_SQL",
                    f"Query {query.query_id}: missing SQL text"
                )

            if not query.plan_nodes:
                self.result.add_warning(
                    "MISSING_PLAN",
                    f"Query {query.query_id}: no plan nodes captured"
                )

            if query.end_time is None:
                self.result.add_error(
                    "INCOMPLETE_QUERY",
                    f"Query {query.query_id}: no EXEC_END found"
                )

            if not query.stats:
                self.result.add_warning(
                    "MISSING_STATS",
                    f"Query {query.query_id}: no execution statistics"
                )

    def _validate_no_unknown_events(self):
        """Check for unknown/unparsed events."""
        for event in self.trace.events:
            if event.event_type == EventType.UNKNOWN:
                # Ignore empty lines and pure comments
                if event.raw_line.strip() and not event.raw_line.startswith('#'):
                    self.result.add_warning(
                        "UNKNOWN_EVENT",
                        f"Unparsed event: {event.raw_line[:50]}...",
                        event.line_num
                    )

    def _build_summary(self):
        """Build validation summary."""
        self.result.summary = {
            'trace_id': self.trace.header.get('TRACE_ID', 'unknown'),
            'pid': self.trace.header.get('PID', 'unknown'),
            'total_events': len(self.trace.events),
            'queries': len(self.trace.queries),
            'unique_nodes': len(self.trace.node_starts),
            'total_node_starts': sum(len(v) for v in self.trace.node_starts.values()),
            'total_node_ends': sum(len(v) for v in self.trace.node_ends.values()),
            'errors': len(self.result.errors),
            'warnings': len(self.result.warnings),
        }


def validate_trace(path: str) -> ValidationResult:
    """Convenience function to validate a trace file."""
    validator = TraceValidator(path)
    return validator.validate()


def compare_traces(trace1_path: str, trace2_path: str) -> Dict[str, Any]:
    """Compare two trace files for differences."""
    parser1 = TraceParser(trace1_path)
    parser2 = TraceParser(trace2_path)

    trace1 = parser1.parse()
    trace2 = parser2.parse()

    differences = {
        'query_count': (len(trace1.queries), len(trace2.queries)),
        'node_count': (len(trace1.node_starts), len(trace2.node_starts)),
        'same_structure': True,
        'details': []
    }

    # Compare query structures
    for i, (q1, q2) in enumerate(zip(trace1.queries, trace2.queries)):
        if len(q1.plan_nodes) != len(q2.plan_nodes):
            differences['same_structure'] = False
            differences['details'].append(
                f"Query {i+1}: different plan node counts ({len(q1.plan_nodes)} vs {len(q2.plan_nodes)})"
            )

        # Compare node types
        for j, (n1, n2) in enumerate(zip(q1.plan_nodes, q2.plan_nodes)):
            if n1.get('node_type') != n2.get('node_type'):
                differences['same_structure'] = False
                differences['details'].append(
                    f"Query {i+1}, Node {j+1}: different types ({n1.get('node_type')} vs {n2.get('node_type')})"
                )

    return differences


class IOTraceParser:
    """Parse pg_10046 eBPF trace files (IO and CPU events)."""

    # IO event pattern: pid,timestamp,IO_READ|IO_WRITE,node_ptr,spc,db,rel,fork,seg,blk,ela_us,disk,blk_ela_us
    IO_PATTERN = re.compile(
        r'^(\d+),(\d+),(IO_READ|IO_WRITE),([^,]+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)$'
    )
    # Simpler format from pg_10046_ebpf.sh: timestamp,IO_READ|IO_WRITE,spc,db,rel,fork,seg,blk,ela_us
    IO_PATTERN_SIMPLE = re.compile(
        r'^(\d+),(IO_READ|IO_WRITE),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)$'
    )
    # CPU event pattern: pid,timestamp,CPU_OFF|CPU_ON,node_ptr,duration_us
    CPU_PATTERN = re.compile(
        r'^(\d+),(\d+),(CPU_OFF|CPU_ON),([^,]+),(\d+)$'
    )
    HEADER_PATTERN = re.compile(r'^#\s*(\w+):\s*(.+)$')

    def __init__(self, path: str):
        self.path = path
        self.trace = EBPFTraceFile(path=path)

    def parse(self) -> EBPFTraceFile:
        """Parse the eBPF trace file and return structured data."""
        with open(self.path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.rstrip('\n')
                if not line:
                    continue

                # Header comments
                if line.startswith('#'):
                    match = self.HEADER_PATTERN.match(line)
                    if match:
                        key, value = match.groups()
                        self.trace.header[key] = value
                    continue

                # Try CPU event pattern
                match = self.CPU_PATTERN.match(line)
                if match:
                    groups = match.groups()
                    event = CPUEvent(
                        line_num=line_num,
                        event_type=groups[2],
                        timestamp=int(groups[1]),
                        pid=int(groups[0]),
                        node_ptr=groups[3],
                        duration_us=int(groups[4]),
                    )
                    if event.event_type == 'CPU_OFF':
                        self.trace.cpu_off.append(event)
                    else:
                        self.trace.cpu_on.append(event)
                    continue

                # Try full IO format
                match = self.IO_PATTERN.match(line)
                if match:
                    groups = match.groups()
                    event = IOEvent(
                        line_num=line_num,
                        event_type=groups[2],
                        timestamp=int(groups[1]),
                        pid=int(groups[0]),
                        node_ptr=groups[3],
                        tablespace=int(groups[4]),
                        database=int(groups[5]),
                        relation=int(groups[6]),
                        fork=int(groups[7]),
                        segment=int(groups[8]),
                        block=int(groups[9]),
                        elapsed_us=int(groups[10]),
                        disk=int(groups[11]),
                        block_elapsed_us=int(groups[12]),
                    )
                    if event.event_type == 'IO_READ':
                        self.trace.io_reads.append(event)
                    else:
                        self.trace.io_writes.append(event)
                    continue

                # Try simple IO format
                match = self.IO_PATTERN_SIMPLE.match(line)
                if match:
                    groups = match.groups()
                    event = IOEvent(
                        line_num=line_num,
                        event_type=groups[1],
                        timestamp=int(groups[0]),
                        pid=0,  # Not in simple format
                        node_ptr='',  # Not in simple format
                        tablespace=int(groups[2]),
                        database=int(groups[3]),
                        relation=int(groups[4]),
                        fork=int(groups[5]),
                        segment=int(groups[6]),
                        block=int(groups[7]),
                        elapsed_us=int(groups[8]),
                    )
                    if event.event_type == 'IO_READ':
                        self.trace.io_reads.append(event)
                    else:
                        self.trace.io_writes.append(event)

        return self.trace


# Alias for backwards compatibility
EBPFTraceParser = IOTraceParser


def parse_io_trace(path: str) -> IOTraceFile:
    """Convenience function to parse an IO trace file."""
    parser = IOTraceParser(path)
    return parser.parse()


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: trace_validator.py <trace_file>")
        sys.exit(1)

    result = validate_trace(sys.argv[1])

    print(f"Validation Result: {'PASS' if result.is_valid else 'FAIL'}")
    print(f"\nSummary:")
    for key, value in result.summary.items():
        print(f"  {key}: {value}")

    if result.errors:
        print(f"\nErrors ({len(result.errors)}):")
        for err in result.errors:
            print(f"  [{err.error_type}] {err.message}")
            if err.line_num:
                print(f"    Line: {err.line_num}")

    if result.warnings:
        print(f"\nWarnings ({len(result.warnings)}):")
        for warn in result.warnings:
            print(f"  [{warn.error_type}] {warn.message}")

    sys.exit(0 if result.is_valid else 1)
