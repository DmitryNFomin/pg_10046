#!/usr/bin/env python3
"""
pg_10046_merge.py - Merge extension and eBPF traces

Combines:
- Extension trace: NODE_MAP (pointer -> node type), SQL text, plan text
- eBPF trace: NODE_START/STOP/IO/WAIT with pointer addresses

Produces unified human-readable report.
"""

import sys
import argparse
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from collections import defaultdict


# PostgreSQL wait event decoding (from pgstat.h)
# Format: event_id -> (class_name, event_name)
WAIT_EVENT_NAMES = {
    # Activity class (0x05)
    0x05000000: ("Activity", "ArchiverMain"),
    0x05000001: ("Activity", "AutoVacuumMain"),
    0x05000002: ("Activity", "BgWriterHibernate"),
    0x05000003: ("Activity", "BgWriterMain"),
    0x05000004: ("Activity", "CheckpointerMain"),
    0x05000005: ("Activity", "LogicalApplyMain"),
    0x05000006: ("Activity", "LogicalLauncherMain"),
    0x05000007: ("Activity", "PgStatMain"),
    0x05000008: ("Activity", "RecoveryWalStream"),
    0x05000009: ("Activity", "SysLoggerMain"),
    0x0500000A: ("Activity", "WalReceiverMain"),
    0x0500000B: ("Activity", "WalSenderMain"),
    0x0500000C: ("Activity", "WalWriterMain"),
    # Client class (0x06)
    0x06000000: ("Client", "ClientRead"),
    0x06000001: ("Client", "ClientWrite"),
    0x06000002: ("Client", "GSSOpenServer"),
    0x06000003: ("Client", "LibPQWalReceiverConnect"),
    0x06000004: ("Client", "LibPQWalReceiverReceive"),
    0x06000005: ("Client", "SSLOpenServer"),
    0x06000006: ("Client", "WalSenderWaitForWAL"),
    0x06000007: ("Client", "WalSenderWriteData"),
    # IO class (0x0A)
    0x0A000000: ("IO", "BufFileRead"),
    0x0A000001: ("IO", "BufFileWrite"),
    0x0A000002: ("IO", "ControlFileRead"),
    0x0A000003: ("IO", "ControlFileSync"),
    0x0A000004: ("IO", "ControlFileSyncUpdate"),
    0x0A000005: ("IO", "ControlFileWrite"),
    0x0A000006: ("IO", "ControlFileWriteUpdate"),
    0x0A000007: ("IO", "CopyFileRead"),
    0x0A000008: ("IO", "CopyFileWrite"),
    0x0A000009: ("IO", "DataFileExtend"),
    0x0A00000A: ("IO", "DataFileFlush"),
    0x0A00000B: ("IO", "DataFileImmediateSync"),
    0x0A00000C: ("IO", "DataFilePrefetch"),
    0x0A00000D: ("IO", "DataFileRead"),
    0x0A00000E: ("IO", "DataFileSync"),
    0x0A00000F: ("IO", "DataFileTruncate"),
    0x0A000010: ("IO", "DataFileWrite"),
    0x0A000011: ("IO", "DSMFillZeroWrite"),
    0x0A000012: ("IO", "LockFileAddToDataDirRead"),
    0x0A000013: ("IO", "LockFileAddToDataDirSync"),
    0x0A000014: ("IO", "LockFileAddToDataDirWrite"),
    0x0A000015: ("IO", "LockFileCreateRead"),
    0x0A000016: ("IO", "LockFileCreateSync"),
    0x0A000017: ("IO", "LockFileCreateWrite"),
    0x0A000018: ("IO", "LockFileReCheckDataDirRead"),
    0x0A000019: ("IO", "LogicalRewriteCheckpointSync"),
    0x0A00001A: ("IO", "LogicalRewriteMappingSync"),
    0x0A00001B: ("IO", "LogicalRewriteMappingWrite"),
    0x0A00001C: ("IO", "LogicalRewriteSync"),
    0x0A00001D: ("IO", "LogicalRewriteTruncate"),
    0x0A00001E: ("IO", "LogicalRewriteWrite"),
    0x0A00001F: ("IO", "RelationMapRead"),
    0x0A000020: ("IO", "RelationMapSync"),
    0x0A000021: ("IO", "RelationMapWrite"),
    0x0A000022: ("IO", "ReorderBufferRead"),
    0x0A000023: ("IO", "ReorderBufferWrite"),
    0x0A000024: ("IO", "ReorderLogicalMappingRead"),
    0x0A000025: ("IO", "ReplicationSlotRead"),
    0x0A000026: ("IO", "ReplicationSlotRestoreSync"),
    0x0A000027: ("IO", "ReplicationSlotSync"),
    0x0A000028: ("IO", "ReplicationSlotWrite"),
    0x0A000029: ("IO", "SLRUFlushSync"),
    0x0A00002A: ("IO", "SLRURead"),
    0x0A00002B: ("IO", "SLRUSync"),
    0x0A00002C: ("IO", "SLRUWrite"),
    0x0A00002D: ("IO", "SnapbuildRead"),
    0x0A00002E: ("IO", "SnapbuildSync"),
    0x0A00002F: ("IO", "SnapbuildWrite"),
    0x0A000030: ("IO", "TimelineHistoryFileSync"),
    0x0A000031: ("IO", "TimelineHistoryFileWrite"),
    0x0A000032: ("IO", "TimelineHistoryRead"),
    0x0A000033: ("IO", "TimelineHistorySync"),
    0x0A000034: ("IO", "TimelineHistoryWrite"),
    0x0A000035: ("IO", "TwophaseFileRead"),
    0x0A000036: ("IO", "TwophaseFileSync"),
    0x0A000037: ("IO", "TwophaseFileWrite"),
    0x0A000038: ("IO", "WALBootstrapSync"),
    0x0A000039: ("IO", "WALBootstrapWrite"),
    0x0A00003A: ("IO", "WALCopyRead"),
    0x0A00003B: ("IO", "WALCopySync"),
    0x0A00003C: ("IO", "WALCopyWrite"),
    0x0A00003D: ("IO", "WALInitSync"),
    0x0A00003E: ("IO", "WALInitWrite"),
    0x0A00003F: ("IO", "WALRead"),
    0x0A000040: ("IO", "WALSenderTimelineHistoryRead"),
    0x0A000041: ("IO", "WALSync"),
    0x0A000042: ("IO", "WALSyncMethodAssign"),
    0x0A000043: ("IO", "WALWrite"),
}

# Wait class names for unknown events
WAIT_CLASS_NAMES = {
    0x01: "LWLock",
    0x03: "Lock",
    0x04: "BufferPin",
    0x05: "Activity",
    0x06: "Client",
    0x07: "Extension",
    0x08: "IPC",
    0x09: "Timeout",
    0x0A: "IO",
}


def decode_wait_event(event_id: int) -> str:
    """Decode wait event ID to human-readable name"""
    if event_id in WAIT_EVENT_NAMES:
        class_name, event_name = WAIT_EVENT_NAMES[event_id]
        return f"{class_name}:{event_name}"
    else:
        # Unknown event - show class and event number
        class_id = (event_id >> 24) & 0xFF
        event_num = event_id & 0xFFFFFF
        class_name = WAIT_CLASS_NAMES.get(class_id, f"0x{class_id:02x}")
        return f"{class_name}:Event{event_num}"


@dataclass
class NodeInfo:
    """Node type information from extension"""
    ptr: str  # pointer address as hex string
    parent_ptr: str
    node_type: str
    depth: int
    target: str  # table name for scan nodes


@dataclass
class NodeStats:
    """Runtime statistics for a node"""
    ptr: str
    parent_ptr: str = ""
    node_type: str = "Unknown"
    target: str = ""
    depth: int = 0
    first_start: int = 0
    last_stop: int = 0
    total_time: int = 0
    call_count: int = 0
    io_count: int = 0
    io_time: int = 0
    wait_count: int = 0
    wait_time: int = 0
    io_blocks: List[tuple] = field(default_factory=list)


@dataclass
class WaitStats:
    """Wait event statistics"""
    event_id: int = 0
    event_name: str = ""
    count: int = 0
    total_time: int = 0


@dataclass
class QueryTrace:
    """Full trace for a query"""
    sql: str = ""
    plan_text: str = ""
    plan_time: int = 0  # Planning time in microseconds
    start_time: int = 0
    end_time: int = 0
    node_map: Dict[str, NodeInfo] = field(default_factory=dict)  # ptr -> NodeInfo
    nodes: Dict[str, NodeStats] = field(default_factory=dict)  # ptr -> NodeStats
    events: List[tuple] = field(default_factory=list)
    wait_events: Dict[int, WaitStats] = field(default_factory=dict)  # event_id -> WaitStats


def parse_extension_trace(filename: str) -> Dict[str, any]:
    """Parse extension trace file"""
    result = {
        'sql': '',
        'plan_text': '',
        'plan_time': 0,  # Planning time in microseconds
        'exec_time': 0,  # Execution time in microseconds
        'node_map': {},  # ptr -> NodeInfo
        'pid': '',
        'timestamp': ''
    }

    try:
        with open(filename, 'r') as f:
            in_plan = False
            in_sql = False
            plan_lines = []
            sql_lines = []

            for line in f:
                # Handle multi-line plan
                if line.strip() == 'PLAN_START':
                    in_plan = True
                    in_sql = False  # SQL ends when plan starts
                    if sql_lines:
                        result['sql'] = ''.join(sql_lines)
                        sql_lines = []
                    plan_lines = []
                    continue
                elif line.strip() == 'PLAN_END':
                    in_plan = False
                    result['plan_text'] = ''.join(plan_lines)
                    continue
                elif in_plan:
                    plan_lines.append(line)
                    continue

                # Handle multi-line SQL (continues until NODE_MAP or PLAN_START)
                if in_sql:
                    if line.startswith('NODE_MAP,') or line.startswith('QUERY_END,'):
                        in_sql = False
                        result['sql'] = ''.join(sql_lines).strip()
                        sql_lines = []
                        # Fall through to process this line
                    else:
                        sql_lines.append(line)
                        continue

                line_stripped = line.strip()
                if not line_stripped:
                    continue

                # Parse header comments for metadata
                if line_stripped.startswith('#'):
                    if line_stripped.startswith('# PID:'):
                        result['pid'] = line_stripped.split(':', 1)[1].strip()
                    elif line_stripped.startswith('# TIMESTAMP:'):
                        result['timestamp'] = line_stripped.split(':', 1)[1].strip()
                    elif line_stripped.startswith('# TIME:'):
                        # Legacy format - try to extract timestamp
                        result['timestamp'] = line_stripped.split(':', 1)[1].strip()
                    continue

                parts = line_stripped.split(',', 5)
                if len(parts) < 2:
                    continue

                event = parts[0]

                if event == 'QUERY_START':
                    # QUERY_START,timestamp,query_id,sql=...
                    # SQL may span multiple lines until NODE_MAP
                    full_line = ','.join(parts)
                    if 'sql=' in full_line:
                        sql_start = full_line.split('sql=', 1)[1]
                        sql_lines = [sql_start + '\n']
                        in_sql = True

                elif event == 'NODE_MAP':
                    # NODE_MAP,ptr,parent_ptr,node_type,depth,target
                    if len(parts) >= 5:
                        ptr = parts[1]
                        parent_ptr = parts[2]
                        node_type = parts[3]
                        depth = int(parts[4]) if parts[4].isdigit() else 0
                        target = parts[5] if len(parts) > 5 else ""

                        result['node_map'][ptr] = NodeInfo(
                            ptr=ptr,
                            parent_ptr=parent_ptr,
                            node_type=node_type,
                            depth=depth,
                            target=target
                        )

                elif event == 'PLAN_TEXT':
                    # Legacy: PLAN_TEXT,text with | instead of newlines
                    result['plan_text'] = ','.join(parts[1:]).replace('|', '\n')

                elif event == 'PLAN_TIME':
                    # PLAN_TIME,elapsed_us
                    try:
                        result['plan_time'] = int(parts[1])
                    except (ValueError, IndexError):
                        pass

                elif event == 'QUERY_END':
                    # QUERY_END,timestamp,query_id,ela=elapsed_us
                    full_line = ','.join(parts)
                    if 'ela=' in full_line:
                        try:
                            ela_str = full_line.split('ela=')[1].split(',')[0].split()[0]
                            result['exec_time'] = int(ela_str)
                        except (ValueError, IndexError):
                            pass

    except FileNotFoundError:
        pass  # Extension trace is optional

    return result


def parse_ebpf_trace(filename: str, node_map: Dict[str, NodeInfo]) -> List[QueryTrace]:
    """Parse eBPF trace file with node type enrichment"""
    queries = []
    current_query = None

    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            parts = line.split(',')
            if len(parts) < 4:
                continue

            try:
                timestamp = int(parts[0])
                event = parts[1]
                ptr = parts[2]  # pointer as hex string
                parent_ptr = parts[3]
                detail = parts[4] if len(parts) > 4 else ""
            except (ValueError, IndexError):
                continue

            if event == 'QUERY_START':
                sql = ""
                if 'sql=' in detail:
                    sql = detail.split('sql=', 1)[1]
                current_query = QueryTrace(
                    sql=sql,
                    start_time=timestamp,
                    node_map=node_map
                )
                queries.append(current_query)

            elif event == 'QUERY_END' and current_query:
                current_query.end_time = timestamp

            elif event == 'NODE_START':
                # Auto-create query if we see NODE_START without QUERY_START
                # (happens when bpftrace loses events)
                if current_query is None and node_map:
                    current_query = QueryTrace(
                        sql="(QUERY_START lost - reconstructed from events)",
                        start_time=timestamp,
                        node_map=node_map
                    )
                    queries.append(current_query)

                if current_query:
                    if ptr not in current_query.nodes:
                        # Look up node type from extension mapping
                        node_info = node_map.get(ptr)
                        current_query.nodes[ptr] = NodeStats(
                            ptr=ptr,
                            parent_ptr=parent_ptr,
                            node_type=node_info.node_type if node_info else "Unknown",
                            target=node_info.target if node_info else "",
                            depth=node_info.depth if node_info else 0,
                            first_start=timestamp
                        )
                    node = current_query.nodes[ptr]
                    node.call_count += 1
                    current_query.events.append((timestamp, 'NODE_START', ptr, parent_ptr, detail))

            elif event == 'NODE_STOP' and current_query:
                if ptr in current_query.nodes:
                    node = current_query.nodes[ptr]
                    node.last_stop = timestamp
                    if 'ela=' in detail:
                        try:
                            ela = int(detail.split('ela=')[1].split()[0])
                            node.total_time += ela
                        except ValueError:
                            pass
                current_query.events.append((timestamp, 'NODE_STOP', ptr, parent_ptr, detail))

            elif event == 'IO' and current_query:
                if ptr not in current_query.nodes:
                    node_info = node_map.get(ptr)
                    current_query.nodes[ptr] = NodeStats(
                        ptr=ptr,
                        node_type=node_info.node_type if node_info else "Unknown",
                        target=node_info.target if node_info else ""
                    )
                node = current_query.nodes[ptr]
                node.io_count += 1

                rel = blk = ela = 0
                for part in detail.split():
                    if part.startswith('rel='):
                        rel = int(part.split('=')[1])
                    elif part.startswith('blk='):
                        blk = int(part.split('=')[1])
                    elif part.startswith('ela='):
                        ela = int(part.split('=')[1])

                node.io_time += ela
                node.io_blocks.append((rel, blk, ela))
                current_query.events.append((timestamp, 'IO', ptr, parent_ptr, detail))

            elif event == 'WAIT' and current_query:
                if ptr not in current_query.nodes:
                    node_info = node_map.get(ptr)
                    current_query.nodes[ptr] = NodeStats(
                        ptr=ptr,
                        node_type=node_info.node_type if node_info else "Unknown",
                        target=node_info.target if node_info else ""
                    )
                node = current_query.nodes[ptr]
                node.wait_count += 1

                ela = 0
                event_id = 0
                for part in detail.split():
                    if part.startswith('ela='):
                        try:
                            ela = int(part.split('=')[1])
                        except ValueError:
                            pass
                    elif part.startswith('event='):
                        # New format: event=0x05000000
                        try:
                            event_id = int(part.split('=')[1], 16)
                        except ValueError:
                            pass
                    elif part.startswith('class='):
                        # Old format: class=0x05 - convert to pseudo event_id
                        try:
                            class_id = int(part.split('=')[1], 16)
                            event_id = class_id << 24  # Put class in high byte
                        except ValueError:
                            pass

                node.wait_time += ela

                # Track wait events by type
                if event_id not in current_query.wait_events:
                    current_query.wait_events[event_id] = WaitStats(
                        event_id=event_id,
                        event_name=decode_wait_event(event_id)
                    )
                current_query.wait_events[event_id].count += 1
                current_query.wait_events[event_id].total_time += ela

                current_query.events.append((timestamp, 'WAIT', ptr, parent_ptr, detail))

    return queries


def format_time(us: int) -> str:
    """Format microseconds as human readable"""
    if us < 1000:
        return f"{us} us"
    elif us < 1000000:
        return f"{us/1000:.2f} ms"
    else:
        return f"{us/1000000:.2f} s"


def print_report(queries: List[QueryTrace], ext_data: Dict, show_timeline: bool = False, limit: int = 50):
    """Print merged report"""

    for i, query in enumerate(queries):
        print(f"\n{'='*80}")
        print(f"QUERY {i+1}")
        print(f"{'='*80}")

        # Show PID and timestamp from extension trace
        pid = ext_data.get('pid', '')
        timestamp = ext_data.get('timestamp', '')
        if pid or timestamp:
            print(f"\nPID: {pid}  TIMESTAMP: {timestamp}")

        # SQL from extension (more complete) or eBPF
        sql = ext_data.get('sql') or query.sql
        if sql:
            print(f"\nSQL: {sql}")

        # Timing summary
        # Use eBPF timing if available, otherwise fall back to extension timing
        total_time = query.end_time - query.start_time if query.end_time else 0
        if total_time == 0:
            # eBPF lost QUERY_END event - use extension's exec_time
            total_time = ext_data.get('exec_time', 0)
        plan_time = ext_data.get('plan_time', 0)

        if plan_time:
            print(f"\nPlanning time:  {format_time(plan_time)}")
        print(f"Execution time: {format_time(total_time)}")
        if plan_time and total_time:
            print(f"Total time:     {format_time(plan_time + total_time)}")

        # Plan text from extension
        plan_text = ext_data.get('plan_text', '')
        if plan_text:
            print(f"\n{'='*80}")
            print("EXECUTION PLAN")
            print(f"{'='*80}")
            for line in plan_text.split('\n')[:20]:  # Limit plan lines
                print(f"  {line}")

        # Node summary with types
        print(f"\n{'='*80}")
        print("NODE SUMMARY")
        print(f"{'='*80}")
        print(f"{'Type':<20} {'Target':<15} {'Calls':>8} {'Time':>12} {'Waits':>8} {'Wait Time':>12}")
        print("-" * 80)

        # Sort nodes by depth (if available) or by pointer
        sorted_nodes = sorted(query.nodes.values(), key=lambda n: (n.depth, n.ptr))

        for node in sorted_nodes:
            if node.ptr == '0' or node.ptr == '0x0':
                # Events with null pointer happened outside node execution context
                # These are from background PostgreSQL processes (WalWriter, BgWriter, etc.)
                if node.call_count == 0 and node.io_count == 0 and node.wait_count == 0:
                    continue
                node_type = "(background)"
                target = ""
            else:
                node_type = node.node_type
                target = node.target[:15] if node.target else ""

            # Indent by depth
            indent = "  " * max(0, node.depth - 1)
            display_type = f"{indent}{node_type}"

            # Combine IO and wait counts/times - IO is a type of wait
            total_waits = node.io_count + node.wait_count
            total_wait_time = node.io_time + node.wait_time

            print(f"{display_type:<20} {target:<15} {node.call_count:>8} "
                  f"{format_time(node.total_time):>12} {total_waits:>8} "
                  f"{format_time(total_wait_time):>12}")

        # IO breakdown
        io_by_node = defaultdict(lambda: defaultdict(list))
        for node in query.nodes.values():
            if node.io_blocks:
                for rel, blk, ela in node.io_blocks:
                    io_by_node[node.node_type or node.ptr][rel].append((blk, ela))

        if io_by_node:
            print(f"\n{'='*80}")
            print("IO BREAKDOWN BY NODE")
            print(f"{'='*80}")

            for node_type, rels in sorted(io_by_node.items()):
                print(f"\n{node_type}:")
                for rel_id, blocks in sorted(rels.items()):
                    total_io_time = sum(ela for _, ela in blocks)
                    print(f"  Relation {rel_id}: {len(blocks)} blocks, {format_time(total_io_time)}")

        # Wait event breakdown
        if query.wait_events:
            print(f"\n{'='*80}")
            print("WAIT EVENT BREAKDOWN")
            print(f"{'='*80}")
            print(f"{'Event':<35} {'Count':>8} {'Total Time':>15} {'Avg Time':>12}")
            print("-" * 72)

            # Sort by total time descending
            sorted_waits = sorted(query.wait_events.values(),
                                  key=lambda w: w.total_time, reverse=True)
            for wait in sorted_waits:
                avg_time = wait.total_time // wait.count if wait.count > 0 else 0
                print(f"{wait.event_name:<35} {wait.count:>8} "
                      f"{format_time(wait.total_time):>15} {format_time(avg_time):>12}")

        # Timeline
        if show_timeline:
            print(f"\n{'='*80}")
            print(f"TIMELINE (first {limit} events)")
            print(f"{'='*80}")

            base_time = query.start_time
            count = 0
            node_map = ext_data.get('node_map', {})

            for timestamp, event, ptr, parent_ptr, detail in query.events:
                if count >= limit:
                    remaining = len(query.events) - count
                    print(f"\n... and {remaining} more events")
                    break

                relative_time = timestamp - base_time
                node_info = node_map.get(ptr)
                node_type = node_info.node_type if node_info else ptr

                print(f"+{format_time(relative_time):>12}  {event:<12} {node_type:<15} {detail}")
                count += 1


def main():
    parser = argparse.ArgumentParser(description='Merge and report pg_10046 traces')
    parser.add_argument('ebpf_trace', help='eBPF trace file')
    parser.add_argument('--ext', '-e', dest='ext_trace', help='Extension trace file')
    parser.add_argument('--timeline', '-t', action='store_true', help='Show event timeline')
    parser.add_argument('--limit', '-l', type=int, default=50, help='Limit timeline events')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')

    args = parser.parse_args()

    # Parse extension trace if provided
    ext_data = {}
    if args.ext_trace:
        ext_data = parse_extension_trace(args.ext_trace)
        print(f"# Loaded extension trace: {args.ext_trace}", file=sys.stderr)
        print(f"# Node mappings: {len(ext_data.get('node_map', {}))}", file=sys.stderr)

    # Parse eBPF trace
    node_map = ext_data.get('node_map', {})
    queries = parse_ebpf_trace(args.ebpf_trace, node_map)

    if not queries:
        print("No queries found in eBPF trace file", file=sys.stderr)
        return 1

    # Redirect output if requested
    if args.output:
        sys.stdout = open(args.output, 'w')

    print_report(queries, ext_data, args.timeline, args.limit)

    if args.output:
        sys.stdout.close()
        print(f"# Report written to: {args.output}", file=sys.stderr)

    return 0


if __name__ == '__main__':
    sys.exit(main())
