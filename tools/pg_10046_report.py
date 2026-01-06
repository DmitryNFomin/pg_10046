#!/usr/bin/env python3
"""
pg_10046_report.py - Parse and format pg_10046 traces

Reads eBPF trace output and produces human-readable reports.
Can merge with extension output (SQL, binds, plan text) when available.
"""

import sys
import argparse
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from collections import defaultdict


@dataclass
class NodeStats:
    """Statistics for a plan node"""
    node_id: int
    parent_id: int = 0
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
class QueryTrace:
    """Full trace for a query"""
    query_id: int
    sql: str = ""
    start_time: int = 0
    end_time: int = 0
    nodes: Dict[int, NodeStats] = field(default_factory=dict)
    events: List[tuple] = field(default_factory=list)


def parse_trace(filename: str) -> List[QueryTrace]:
    """Parse eBPF trace file"""
    queries = []
    current_query = None

    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue

            parts = line.split(',')
            if len(parts) < 4:
                continue

            try:
                timestamp = int(parts[0])
                event = parts[1]
                node_id = int(parts[2])
                parent_id = int(parts[3])
                detail = parts[4] if len(parts) > 4 else ""
            except (ValueError, IndexError):
                continue

            if event == 'QUERY_START':
                # Extract SQL from detail
                sql = ""
                if 'sql=' in detail:
                    sql = detail.split('sql=', 1)[1]
                current_query = QueryTrace(
                    query_id=node_id,
                    sql=sql,
                    start_time=timestamp
                )
                queries.append(current_query)

            elif event == 'QUERY_END' and current_query:
                current_query.end_time = timestamp

            elif event == 'NODE_START' and current_query:
                if node_id not in current_query.nodes:
                    current_query.nodes[node_id] = NodeStats(
                        node_id=node_id,
                        parent_id=parent_id,
                        first_start=timestamp
                    )
                node = current_query.nodes[node_id]
                node.call_count += 1
                current_query.events.append((timestamp, 'NODE_START', node_id, parent_id, detail))

            elif event == 'NODE_STOP' and current_query:
                if node_id in current_query.nodes:
                    node = current_query.nodes[node_id]
                    node.last_stop = timestamp
                    # Extract elapsed time
                    if 'ela=' in detail:
                        try:
                            ela = int(detail.split('ela=')[1].split()[0])
                            node.total_time += ela
                        except ValueError:
                            pass
                current_query.events.append((timestamp, 'NODE_STOP', node_id, parent_id, detail))

            elif event == 'IO' and current_query:
                if node_id not in current_query.nodes:
                    current_query.nodes[node_id] = NodeStats(node_id=node_id)
                node = current_query.nodes[node_id]
                node.io_count += 1

                # Parse IO details
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
                current_query.events.append((timestamp, 'IO', node_id, parent_id, detail))

            elif event == 'WAIT' and current_query:
                if node_id not in current_query.nodes:
                    current_query.nodes[node_id] = NodeStats(node_id=node_id)
                node = current_query.nodes[node_id]
                node.wait_count += 1

                if 'ela=' in detail:
                    try:
                        ela = int(detail.split('ela=')[1].split()[0])
                        node.wait_time += ela
                    except ValueError:
                        pass
                current_query.events.append((timestamp, 'WAIT', node_id, parent_id, detail))

    return queries


def format_time(us: int) -> str:
    """Format microseconds as human readable"""
    if us < 1000:
        return f"{us} us"
    elif us < 1000000:
        return f"{us/1000:.2f} ms"
    else:
        return f"{us/1000000:.2f} s"


def print_summary(queries: List[QueryTrace]):
    """Print summary report"""
    for i, query in enumerate(queries):
        print(f"\n{'='*70}")
        print(f"QUERY {i+1}")
        print(f"{'='*70}")

        if query.sql:
            print(f"\nSQL: {query.sql}")

        total_time = query.end_time - query.start_time if query.end_time else 0
        print(f"\nTotal execution time: {format_time(total_time)}")

        # Node summary
        print(f"\n{'='*70}")
        print("NODE SUMMARY")
        print(f"{'='*70}")
        print(f"{'Node':>6} {'Parent':>6} {'Calls':>8} {'Time':>12} {'IO':>6} {'IO Time':>12} {'Waits':>6} {'Wait Time':>12}")
        print("-" * 70)

        for node_id in sorted(query.nodes.keys()):
            node = query.nodes[node_id]
            if node_id == 0 and node.call_count == 0:
                # Background node (non-query IO/waits)
                continue
            print(f"{node.node_id:>6} {node.parent_id:>6} {node.call_count:>8} "
                  f"{format_time(node.total_time):>12} {node.io_count:>6} "
                  f"{format_time(node.io_time):>12} {node.wait_count:>6} "
                  f"{format_time(node.wait_time):>12}")

        # IO details per node
        io_by_rel = defaultdict(lambda: defaultdict(list))
        for node_id, node in query.nodes.items():
            for rel, blk, ela in node.io_blocks:
                io_by_rel[node_id][rel].append((blk, ela))

        if any(io_by_rel.values()):
            print(f"\n{'='*70}")
            print("IO BREAKDOWN BY NODE")
            print(f"{'='*70}")

            for node_id in sorted(io_by_rel.keys()):
                if node_id == 0:
                    print(f"\nNode 0 (Planning/Background):")
                else:
                    print(f"\nNode {node_id}:")

                for rel_id, blocks in sorted(io_by_rel[node_id].items()):
                    total_io_time = sum(ela for _, ela in blocks)
                    print(f"  Relation {rel_id}: {len(blocks)} blocks, {format_time(total_io_time)}")


def print_timeline(queries: List[QueryTrace], limit: int = 100):
    """Print timeline of events"""
    for i, query in enumerate(queries):
        print(f"\n{'='*70}")
        print(f"QUERY {i+1} TIMELINE (first {limit} events)")
        print(f"{'='*70}")

        if query.sql:
            print(f"SQL: {query.sql}\n")

        base_time = query.start_time
        count = 0

        for timestamp, event, node_id, parent_id, detail in query.events:
            if count >= limit:
                remaining = len(query.events) - count
                print(f"\n... and {remaining} more events")
                break

            relative_time = timestamp - base_time
            print(f"+{format_time(relative_time):>12}  {event:<12} Node={node_id} {detail}")
            count += 1


def main():
    parser = argparse.ArgumentParser(description='Parse and format pg_10046 traces')
    parser.add_argument('tracefile', help='eBPF trace file to parse')
    parser.add_argument('--timeline', '-t', action='store_true',
                        help='Show event timeline')
    parser.add_argument('--limit', '-l', type=int, default=100,
                        help='Limit timeline events (default: 100)')

    args = parser.parse_args()

    queries = parse_trace(args.tracefile)

    if not queries:
        print("No queries found in trace file")
        return 1

    print_summary(queries)

    if args.timeline:
        print_timeline(queries, args.limit)

    return 0


if __name__ == '__main__':
    sys.exit(main())
