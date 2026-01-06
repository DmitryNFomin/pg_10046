#!/usr/bin/env python3
"""
pg_tracer.py - PostgreSQL Oracle 10046-style tracer using BCC/eBPF

This is a PoC demonstrating real-time plan node tracing, wait events,
and IO operations using eBPF.

Usage:
    sudo python3 pg_tracer.py --pid <backend_pid> [--output trace.trc]

Requirements:
    - PostgreSQL with debug symbols
    - BCC (python3-bpfcc package)
    - Root privileges

This script:
1. Attaches uprobes to PostgreSQL functions
2. Captures real-time events via ring buffer
3. Writes Oracle 10046-style trace file
"""

import argparse
import ctypes
import os
import signal
import sys
import time
from datetime import datetime

try:
    from bcc import BPF
except ImportError:
    print("Error: BCC not installed. Run: apt install python3-bpfcc")
    sys.exit(1)


# eBPF program
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>

/* Event types */
#define EVENT_QUERY_START   1
#define EVENT_QUERY_END     2
#define EVENT_NODE_START    3
#define EVENT_NODE_STOP     4
#define EVENT_WAIT_START    5
#define EVENT_WAIT_END      6
#define EVENT_IO_READ       7

/* Event structure sent to userspace */
struct event_t {
    u32 pid;
    u32 tid;
    u8  event_type;
    u64 timestamp;

    /* Query info */
    char query[256];

    /* Node info */
    u32 node_depth;

    /* Wait info */
    u32 wait_event;
    u64 wait_ela_us;

    /* IO info */
    u32 rel_oid;
    u32 block_num;
    u64 io_ela_us;
};

BPF_RINGBUF_OUTPUT(events, 1 << 16);

/* Per-thread state */
BPF_HASH(node_start_ts, u32, u64);
BPF_HASH(node_depth, u32, u32);
BPF_HASH(wait_start_ts, u32, u64);
BPF_HASH(wait_event_info, u32, u32);
BPF_HASH(io_start_ts, u32, u64);
BPF_HASH(io_rel, u32, u32);
BPF_HASH(io_blk, u32, u32);
BPF_HASH(exec_start_ts, u32, u64);

/* Query start - standard_ExecutorRun */
int trace_executor_run(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    struct event_t *e = events.ringbuf_reserve(sizeof(struct event_t));
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = tid;
    e->event_type = EVENT_QUERY_START;
    e->timestamp = ts;

    /* Read QueryDesc->sourceText */
    void *qd = (void *)PT_REGS_PARM1(ctx);
    void *sql_ptr;
    bpf_probe_read_user(&sql_ptr, sizeof(void *), qd + QUERYDESC_SOURCETEXT_OFFSET);
    bpf_probe_read_user_str(e->query, sizeof(e->query), sql_ptr);

    events.ringbuf_submit(e, 0);

    exec_start_ts.update(&tid, &ts);
    return 0;
}

/* Query end */
int trace_executor_run_ret(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    u64 *start = exec_start_ts.lookup(&tid);
    if (!start) return 0;

    u64 ts = bpf_ktime_get_ns();

    struct event_t *e = events.ringbuf_reserve(sizeof(struct event_t));
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = tid;
    e->event_type = EVENT_QUERY_END;
    e->timestamp = ts;
    e->wait_ela_us = (ts - *start) / 1000;  /* reuse field for total time */

    events.ringbuf_submit(e, 0);

    exec_start_ts.delete(&tid);
    return 0;
}

/* Node start */
int trace_instr_start(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    /* Increment depth */
    u32 zero = 0;
    u32 *depth = node_depth.lookup_or_try_init(&tid, &zero);
    if (depth) {
        (*depth)++;
    }

    node_start_ts.update(&tid, &ts);

    struct event_t *e = events.ringbuf_reserve(sizeof(struct event_t));
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = tid;
    e->event_type = EVENT_NODE_START;
    e->timestamp = ts;
    e->node_depth = depth ? *depth : 1;

    events.ringbuf_submit(e, 0);
    return 0;
}

/* Node stop */
int trace_instr_stop(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    u64 *start = node_start_ts.lookup(&tid);

    struct event_t *e = events.ringbuf_reserve(sizeof(struct event_t));
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = tid;
    e->event_type = EVENT_NODE_STOP;
    e->timestamp = ts;

    if (start) {
        e->wait_ela_us = (ts - *start) / 1000;
        node_start_ts.delete(&tid);
    }

    u32 *depth = node_depth.lookup(&tid);
    if (depth) {
        e->node_depth = *depth;
        if (*depth > 0) (*depth)--;
    }

    events.ringbuf_submit(e, 0);
    return 0;
}

/* Wait start */
int trace_wait_start(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    u32 event = (u32)PT_REGS_PARM5(ctx);  /* wait_event_info is 5th param */

    wait_start_ts.update(&tid, &ts);
    wait_event_info.update(&tid, &event);
    return 0;
}

/* Wait end */
int trace_wait_end(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    u64 *start = wait_start_ts.lookup(&tid);
    u32 *event = wait_event_info.lookup(&tid);
    if (!start || !event) return 0;

    u64 ela_us = (ts - *start) / 1000;

    /* Only report waits > 10us to reduce noise */
    if (ela_us < 10) {
        wait_start_ts.delete(&tid);
        wait_event_info.delete(&tid);
        return 0;
    }

    struct event_t *e = events.ringbuf_reserve(sizeof(struct event_t));
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = tid;
    e->event_type = EVENT_WAIT_END;
    e->timestamp = ts;
    e->wait_event = *event;
    e->wait_ela_us = ela_us;

    events.ringbuf_submit(e, 0);

    wait_start_ts.delete(&tid);
    wait_event_info.delete(&tid);
    return 0;
}

/* IO read start */
int trace_mdread(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    void *smgr = (void *)PT_REGS_PARM1(ctx);
    u32 rel_oid;
    bpf_probe_read_user(&rel_oid, sizeof(u32), smgr + 8);  /* relNode offset */

    u32 blk = (u32)PT_REGS_PARM3(ctx);

    io_start_ts.update(&tid, &ts);
    io_rel.update(&tid, &rel_oid);
    io_blk.update(&tid, &blk);
    return 0;
}

/* IO read end */
int trace_mdread_ret(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    u64 *start = io_start_ts.lookup(&tid);
    u32 *rel = io_rel.lookup(&tid);
    u32 *blk = io_blk.lookup(&tid);
    if (!start) return 0;

    struct event_t *e = events.ringbuf_reserve(sizeof(struct event_t));
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = tid;
    e->event_type = EVENT_IO_READ;
    e->timestamp = ts;
    e->rel_oid = rel ? *rel : 0;
    e->block_num = blk ? *blk : 0;
    e->io_ela_us = (ts - *start) / 1000;

    events.ringbuf_submit(e, 0);

    io_start_ts.delete(&tid);
    io_rel.delete(&tid);
    io_blk.delete(&tid);
    return 0;
}
"""

# Event types
EVENT_QUERY_START = 1
EVENT_QUERY_END = 2
EVENT_NODE_START = 3
EVENT_NODE_STOP = 4
EVENT_WAIT_START = 5
EVENT_WAIT_END = 6
EVENT_IO_READ = 7

# Wait event class names
WAIT_CLASSES = {
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


class PGTracer:
    def __init__(self, pid, pg_path, output_file):
        self.pid = pid
        self.pg_path = pg_path
        self.output_file = output_file
        self.bpf = None
        self.cursor_id = 0

        # Get QueryDesc->sourceText offset using DWARF or hardcode
        # For PG13 x86_64: typically 0x10 (16)
        # For PG13 ARM64: verify with gdb
        self.querydesc_sourcetext_offset = 0x10

    def get_struct_offset(self, struct_name, field_name):
        """Get struct field offset using gdb (for future enhancement)"""
        # TODO: Use pyelftools or gdb to get actual offsets
        # For now, return hardcoded values
        offsets = {
            ("QueryDesc", "sourceText"): 0x10,
            ("SMgrRelationData", "relNode"): 8,
        }
        return offsets.get((struct_name, field_name), 0)

    def start(self):
        # Prepare BPF program with correct offsets
        program = BPF_PROGRAM.replace(
            "QUERYDESC_SOURCETEXT_OFFSET",
            str(self.querydesc_sourcetext_offset)
        )

        # Load BPF program
        self.bpf = BPF(text=program)

        # Attach probes
        self.bpf.attach_uprobe(
            name=self.pg_path,
            sym="standard_ExecutorRun",
            fn_name="trace_executor_run",
            pid=self.pid
        )
        self.bpf.attach_uretprobe(
            name=self.pg_path,
            sym="standard_ExecutorRun",
            fn_name="trace_executor_run_ret",
            pid=self.pid
        )
        self.bpf.attach_uprobe(
            name=self.pg_path,
            sym="InstrStartNode",
            fn_name="trace_instr_start",
            pid=self.pid
        )
        self.bpf.attach_uprobe(
            name=self.pg_path,
            sym="InstrStopNode",
            fn_name="trace_instr_stop",
            pid=self.pid
        )
        self.bpf.attach_uprobe(
            name=self.pg_path,
            sym="WaitEventSetWait",
            fn_name="trace_wait_start",
            pid=self.pid
        )
        self.bpf.attach_uretprobe(
            name=self.pg_path,
            sym="WaitEventSetWait",
            fn_name="trace_wait_end",
            pid=self.pid
        )
        self.bpf.attach_uprobe(
            name=self.pg_path,
            sym="mdread",
            fn_name="trace_mdread",
            pid=self.pid
        )
        self.bpf.attach_uretprobe(
            name=self.pg_path,
            sym="mdread",
            fn_name="trace_mdread_ret",
            pid=self.pid
        )

        # Write trace header
        self.write_header()

        # Set up ring buffer callback
        self.bpf["events"].open_ring_buffer(self.handle_event)

        print(f"Tracing PID {self.pid}... Press Ctrl+C to stop.")

        try:
            while True:
                self.bpf.ring_buffer_poll()
        except KeyboardInterrupt:
            print("\nStopping trace...")

    def write_header(self):
        with open(self.output_file, "w") as f:
            f.write("*** PG_10046 TRACE FILE ***\n")
            f.write(f"*** PID: {self.pid} ***\n")
            f.write(f"*** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ***\n")
            f.write("*** PostgreSQL eBPF Tracer ***\n")
            f.write("=" * 50 + "\n\n")

    def handle_event(self, ctx, data, size):
        event = self.bpf["events"].event(data)

        with open(self.output_file, "a") as f:
            ts_us = event.timestamp // 1000

            if event.event_type == EVENT_QUERY_START:
                self.cursor_id += 1
                query = event.query.decode('utf-8', errors='replace').rstrip('\x00')
                f.write(f"\nPARSING IN CURSOR #{self.cursor_id} tim={ts_us}\n")
                f.write(f"{query}\n")
                f.write("END OF STMT\n")

            elif event.event_type == EVENT_QUERY_END:
                f.write(f"\nEXEC #{self.cursor_id} e={event.wait_ela_us} us\n")

            elif event.event_type == EVENT_NODE_START:
                f.write(f"NODE_START #{self.cursor_id} depth={event.node_depth} tim={ts_us}\n")

            elif event.event_type == EVENT_NODE_STOP:
                f.write(f"NODE_STOP  #{self.cursor_id} depth={event.node_depth} ela={event.wait_ela_us} us\n")

            elif event.event_type == EVENT_WAIT_END:
                wait_class = (event.wait_event >> 24) & 0xFF
                wait_id = event.wait_event & 0xFFFFFF
                class_name = WAIT_CLASSES.get(wait_class, f"0x{wait_class:02x}")
                f.write(f"WAIT #{self.cursor_id} class={class_name} id=0x{wait_id:06x} ela={event.wait_ela_us} us\n")

            elif event.event_type == EVENT_IO_READ:
                f.write(f"IO #{self.cursor_id} rel={event.rel_oid} blk={event.block_num} ela={event.io_ela_us} us\n")


def find_postgres_binary():
    """Find PostgreSQL binary path"""
    paths = [
        "/usr/lib/postgresql/13/bin/postgres",
        "/usr/lib/postgresql/14/bin/postgres",
        "/usr/lib/postgresql/15/bin/postgres",
        "/usr/pgsql-13/bin/postgres",
        "/usr/local/pgsql/bin/postgres",
    ]
    for p in paths:
        if os.path.exists(p):
            return p
    return None


def main():
    parser = argparse.ArgumentParser(description="PostgreSQL Oracle 10046-style tracer")
    parser.add_argument("--pid", "-p", type=int, required=True, help="PostgreSQL backend PID")
    parser.add_argument("--output", "-o", default="pg_trace.trc", help="Output trace file")
    parser.add_argument("--postgres", default=None, help="Path to postgres binary")
    args = parser.parse_args()

    # Find postgres binary
    pg_path = args.postgres or find_postgres_binary()
    if not pg_path:
        print("Error: Cannot find postgres binary. Use --postgres to specify path.")
        sys.exit(1)

    if not os.path.exists(pg_path):
        print(f"Error: postgres binary not found at {pg_path}")
        sys.exit(1)

    print(f"Using postgres binary: {pg_path}")
    print(f"Tracing PID: {args.pid}")
    print(f"Output file: {args.output}")

    tracer = PGTracer(args.pid, pg_path, args.output)
    tracer.start()


if __name__ == "__main__":
    main()
