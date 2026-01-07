#!/usr/bin/env python3
"""
pg_10046d - eBPF Trace Daemon for pg_10046

Global bpftrace approach:
- One bpftrace instance traces ALL postgres backends continuously
- Daemon filters output by active PIDs
- START/STOP commands instantly enable/disable tracing for a PID (no probe attach delay)

Usage:
    sudo pg_10046d.py [--socket /var/run/pg_10046.sock] [--trace-dir /tmp]

Protocol:
    START <pid> <uuid>  - Start tracing for backend PID (instant)
    STOP <pid>          - Stop tracing for backend PID
    STATUS <pid>        - Get status of tracing for PID
    LIST                - List all active traces
    SHUTDOWN            - Stop daemon
"""

import os
import sys
import signal
import socket
import subprocess
import threading
import argparse
import logging
import time
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Set
from collections import defaultdict

# Configuration
DEFAULT_SOCKET = "/var/run/pg_10046.sock"
DEFAULT_TRACE_DIR = "/tmp"
BPFTRACE_PATH = "/usr/bin/bpftrace"
POSTGRES_PATH = "/usr/pgsql-13/bin/postgres"

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
log = logging.getLogger("pg_10046d")


class TraceSession:
    """Represents an active tracing session for a PostgreSQL backend."""

    def __init__(self, pid: int, uuid: str, trace_file: str):
        self.pid = pid
        self.uuid = uuid
        self.trace_file = trace_file
        self.trace_fd = None
        self.start_time = datetime.now()
        self.io_count = 0
        self.start_timestamp = None  # First event timestamp

    def open(self):
        self.trace_fd = open(self.trace_file, 'w')
        # Write header
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        trace_id = f"{self.pid}_{timestamp}"
        self.trace_fd.write(f"# PG_10046 EBPF TRACE\n")
        self.trace_fd.write(f"# TRACE_ID: {trace_id}\n")
        self.trace_fd.write(f"# TRACE_UUID: {self.uuid}\n")
        self.trace_fd.write(f"# PID: {self.pid}\n")
        self.trace_fd.write(f"# FORMAT: ts_us,EVENT,node_ptr,...\n")
        self.trace_fd.write(f"# EVENTS:\n")
        self.trace_fd.write(f"#   IO_READ:  node_ptr,spc,db,rel,fork,seg,blk,ela_us,disk,blk_ela_us\n")
        self.trace_fd.write(f"#   IO_WRITE: node_ptr,spc,db,rel,fork,seg,blk,ela_us,disk,blk_ela_us\n")
        self.trace_fd.write(f"#   BUF_REQ:  node_ptr,gap_from_node=N\n")
        self.trace_fd.write(f"#   CPU_OFF:  node_ptr,on_cpu_duration_us (going off-CPU)\n")
        self.trace_fd.write(f"#   CPU_ON:   node_ptr,off_cpu_duration_us (coming on-CPU)\n")
        self.trace_fd.write(f"# disk: 0=OS_cache, 1=real_disk_IO\n")
        self.trace_fd.write(f"#\n")
        self.trace_fd.flush()

    def write_event(self, line: str):
        if self.trace_fd:
            self.trace_fd.write(line)
            self.trace_fd.flush()
            self.io_count += 1

    def close(self):
        if self.trace_fd:
            self.trace_fd.write(f"\n# END_TIME: {int(time.time() * 1000000)}\n")
            self.trace_fd.write(f"# IO_EVENTS: {self.io_count}\n")
            self.trace_fd.close()
            self.trace_fd = None


class TraceDaemon:
    """Daemon that manages eBPF tracing with global bpftrace."""

    # Global bpftrace script - traces ALL postgres backends, outputs all events
    BPFTRACE_SCRIPT = '''#!/usr/bin/env bpftrace
#define RELSEG_SIZE 131072

BEGIN {
    printf("# BPFTRACE_READY\\n");
}

/*
 * Track current executing node via InstrStartNode
 * arg0 = Instrumentation* (correlates with extension's NODE_MAP)
 */
uprobe:POSTGRES_PATH:InstrStartNode {
    @current_node[tid] = arg0;
    @node_start_ts[tid] = nsecs;
    @on_cpu_start[tid] = nsecs;  /* Start tracking CPU time */
}

/*
 * CPU scheduling: track on-CPU vs off-CPU time
 * Only for threads currently executing instrumented nodes
 * Note: kernel pid = userspace tid (thread ID)
 */
tracepoint:sched:sched_switch {
    /* Thread going OFF-CPU */
    if (@current_node[args->prev_pid]) {
        $on_dur = (uint64)0;
        if (@on_cpu_start[args->prev_pid]) {
            $on_dur = (nsecs - @on_cpu_start[args->prev_pid]) / 1000;
        }
        @off_cpu_start[args->prev_pid] = nsecs;
        printf("%d,%lu,CPU_OFF,0x%lx,%lu\\n",
               args->prev_pid, nsecs / 1000,
               @current_node[args->prev_pid], $on_dur);
    }

    /* Thread coming ON-CPU */
    if (@current_node[args->next_pid]) {
        $off_dur = (uint64)0;
        if (@off_cpu_start[args->next_pid]) {
            $off_dur = (nsecs - @off_cpu_start[args->next_pid]) / 1000;
        }
        @on_cpu_start[args->next_pid] = nsecs;
        printf("%d,%lu,CPU_ON,0x%lx,%lu\\n",
               args->next_pid, nsecs / 1000,
               @current_node[args->next_pid], $off_dur);
        delete(@off_cpu_start[args->next_pid]);
    }
}

/*
 * Track time from node start to first ReadBuffer call
 */
uprobe:POSTGRES_PATH:ReadBufferExtended /@node_start_ts[tid]/ {
    $gap = (nsecs - @node_start_ts[tid]) / 1000;
    printf("%d,%lu,BUF_REQ,0x%lx,gap_from_node=%lu\\n",
           pid, nsecs / 1000, @current_node[tid], $gap);
    delete(@node_start_ts[tid]);  /* Only first buffer request per node */
}

uprobe:POSTGRES_PATH:mdread {
    @rd_start[tid] = nsecs;
    @rd_spc[tid] = *(uint32*)(arg0 + 0);
    @rd_db[tid]  = *(uint32*)(arg0 + 4);
    @rd_rel[tid] = *(uint32*)(arg0 + 8);
    @rd_fork[tid] = arg1;
    @rd_blk[tid] = arg2;
    @rd_seg[tid] = arg2 / RELSEG_SIZE;
    @rd_node[tid] = @current_node[tid];
    @in_mdread[tid] = 1;
    @blk_issued[tid] = 0;
    @blk_ela[tid] = 0;
}

/*
 * Block layer: track actual disk I/O (only fires for real disk reads, not page cache)
 * Only track if we're inside mdread
 */
tracepoint:block:block_rq_issue /@in_mdread[tid]/ {
    @blk_issued[tid] = 1;
    @blk_start[tid] = nsecs;
}

tracepoint:block:block_rq_complete /@blk_start[tid]/ {
    @blk_ela[tid] = (nsecs - @blk_start[tid]) / 1000;
    delete(@blk_start[tid]);
}

uretprobe:POSTGRES_PATH:mdread /@rd_start[tid]/ {
    $ela = (nsecs - @rd_start[tid]) / 1000;
    $disk = @blk_issued[tid];
    $blk_ela = @blk_ela[tid];
    /* Format: ...,mdread_ela,disk(0=cache/1=disk),blk_ela */
    printf("%d,%lu,IO_READ,0x%lx,%u,%u,%u,%u,%u,%u,%lu,%lu,%lu\\n",
           pid,
           nsecs / 1000,
           @rd_node[tid],
           @rd_spc[tid], @rd_db[tid], @rd_rel[tid],
           @rd_fork[tid], @rd_seg[tid], @rd_blk[tid],
           $ela, $disk, $blk_ela);
    delete(@rd_start[tid]); delete(@rd_spc[tid]); delete(@rd_db[tid]);
    delete(@rd_rel[tid]); delete(@rd_fork[tid]); delete(@rd_blk[tid]);
    delete(@rd_seg[tid]); delete(@rd_node[tid]);
    delete(@in_mdread[tid]); delete(@blk_issued[tid]); delete(@blk_ela[tid]);
}

uprobe:POSTGRES_PATH:mdwrite {
    @wr_start[tid] = nsecs;
    @wr_spc[tid] = *(uint32*)(arg0 + 0);
    @wr_db[tid]  = *(uint32*)(arg0 + 4);
    @wr_rel[tid] = *(uint32*)(arg0 + 8);
    @wr_fork[tid] = arg1;
    @wr_blk[tid] = arg2;
    @wr_seg[tid] = arg2 / RELSEG_SIZE;
    @wr_node[tid] = @current_node[tid];
    @in_mdwrite[tid] = 1;
    @blk_wr_issued[tid] = 0;
    @blk_wr_ela[tid] = 0;
}

/*
 * Block layer for writes
 */
tracepoint:block:block_rq_issue /@in_mdwrite[tid]/ {
    @blk_wr_issued[tid] = 1;
    @blk_wr_start[tid] = nsecs;
}

tracepoint:block:block_rq_complete /@blk_wr_start[tid]/ {
    @blk_wr_ela[tid] = (nsecs - @blk_wr_start[tid]) / 1000;
    delete(@blk_wr_start[tid]);
}

uretprobe:POSTGRES_PATH:mdwrite /@wr_start[tid]/ {
    $ela = (nsecs - @wr_start[tid]) / 1000;
    $disk = @blk_wr_issued[tid];
    $blk_ela = @blk_wr_ela[tid];
    printf("%d,%lu,IO_WRITE,0x%lx,%u,%u,%u,%u,%u,%u,%lu,%lu,%lu\\n",
           pid,
           nsecs / 1000,
           @wr_node[tid],
           @wr_spc[tid], @wr_db[tid], @wr_rel[tid],
           @wr_fork[tid], @wr_seg[tid], @wr_blk[tid],
           $ela, $disk, $blk_ela);
    delete(@wr_start[tid]); delete(@wr_spc[tid]); delete(@wr_db[tid]);
    delete(@wr_rel[tid]); delete(@wr_fork[tid]); delete(@wr_blk[tid]);
    delete(@wr_seg[tid]); delete(@wr_node[tid]);
    delete(@in_mdwrite[tid]); delete(@blk_wr_issued[tid]); delete(@blk_wr_ela[tid]);
}

END {
    printf("# BPFTRACE_END\\n");
    clear(@current_node);
}
'''

    def __init__(self, socket_path: str, trace_dir: str, postgres_path: str):
        self.socket_path = socket_path
        self.trace_dir = trace_dir
        self.postgres_path = postgres_path
        self.sessions: Dict[int, TraceSession] = {}
        self.lock = threading.Lock()
        self.running = True
        self.server_socket = None
        self.bpftrace_proc = None
        self.bpftrace_ready = False

        # Prepare bpftrace script
        self.bpftrace_script = self.BPFTRACE_SCRIPT.replace('POSTGRES_PATH', postgres_path)

    def start_global_bpftrace(self):
        """Start the global bpftrace instance."""

        # Write bpftrace script to temp file
        script_file = "/tmp/pg_10046_global.bt"
        with open(script_file, 'w') as f:
            f.write(self.bpftrace_script)

        log.info("Starting global bpftrace...")

        self.bpftrace_proc = subprocess.Popen(
            [BPFTRACE_PATH, script_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True
        )

        # Wait for READY signal
        while True:
            line = self.bpftrace_proc.stdout.readline()
            if not line:
                log.error("bpftrace died during startup")
                return False
            line = line.decode('utf-8', errors='replace').strip()
            if '# BPFTRACE_READY' in line:
                self.bpftrace_ready = True
                log.info("Global bpftrace ready - probes attached")
                break
            elif 'Attaching' in line:
                log.info(f"bpftrace: {line}")

        # Start reader thread
        reader_thread = threading.Thread(target=self._read_bpftrace_output, daemon=True)
        reader_thread.start()

        return True

    def _read_bpftrace_output(self):
        """Read bpftrace output and dispatch to active sessions."""

        # Regex to parse output: pid,timestamp,event,rest
        event_pattern = re.compile(r'^(\d+),(\d+),(IO_READ|IO_WRITE|BUF_REQ|CPU_OFF|CPU_ON),(.*)$')

        while self.running and self.bpftrace_proc:
            try:
                line = self.bpftrace_proc.stdout.readline()
                if not line:
                    break

                line_str = line.decode('utf-8', errors='replace')

                # Skip comments
                if line_str.startswith('#'):
                    continue

                # Parse event
                match = event_pattern.match(line_str.strip())
                if match:
                    pid = int(match.group(1))
                    timestamp = match.group(2)
                    event_type = match.group(3)
                    rest = match.group(4)

                    # Check if this PID is being traced
                    with self.lock:
                        if pid in self.sessions:
                            session = self.sessions[pid]
                            # Write event without PID prefix
                            output_line = f"{timestamp},{event_type},{rest}\n"
                            session.write_event(output_line)

            except Exception as e:
                if self.running:
                    log.error(f"Error reading bpftrace output: {e}")

        log.info("bpftrace reader thread ended")

    def stop_global_bpftrace(self):
        """Stop the global bpftrace instance."""
        if self.bpftrace_proc:
            log.info("Stopping global bpftrace...")
            self.bpftrace_proc.send_signal(signal.SIGINT)
            try:
                self.bpftrace_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.bpftrace_proc.kill()
                self.bpftrace_proc.wait()
            self.bpftrace_proc = None

    def start_trace(self, pid: int, uuid: str) -> tuple:
        """Start tracing for a PostgreSQL backend (instant - just adds to active set)."""

        with self.lock:
            # Check if already tracing this PID
            if pid in self.sessions:
                return False, f"Already tracing PID {pid}"

            # Verify PID is a postgres process
            try:
                with open(f"/proc/{pid}/comm", 'r') as f:
                    comm = f.read().strip()
                    if 'postgres' not in comm and 'postmaster' not in comm:
                        return False, f"PID {pid} is not a postgres process ({comm})"
            except FileNotFoundError:
                return False, f"PID {pid} does not exist"

            # Generate trace file name
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            trace_id = f"{pid}_{timestamp}"
            trace_file = os.path.join(self.trace_dir, f"pg_10046_ebpf_{trace_id}.trc")

            # Create session and open trace file
            session = TraceSession(pid, uuid, trace_file)
            session.open()

            # Add to active sessions - events will now be captured
            self.sessions[pid] = session

            log.info(f"Started tracing PID {pid}, UUID {uuid}, file {trace_file}")
            return True, trace_file

    def stop_trace(self, pid: int) -> tuple:
        """Stop tracing for a PostgreSQL backend."""

        with self.lock:
            if pid not in self.sessions:
                return False, f"No active trace for PID {pid}"

            session = self.sessions[pid]
            io_count = session.io_count
            trace_file = session.trace_file

            # Close trace file
            session.close()

            # Remove from active sessions
            del self.sessions[pid]

            log.info(f"Stopped tracing PID {pid}, {io_count} IO events")
            return True, f"{trace_file} ({io_count} IO events)"

    def get_status(self, pid: int) -> tuple:
        """Get status of tracing for a PID."""

        with self.lock:
            if pid not in self.sessions:
                return False, "INACTIVE"

            session = self.sessions[pid]
            return True, f"ACTIVE {session.trace_file} {session.io_count}"

    def list_sessions(self) -> str:
        """List all active tracing sessions."""

        with self.lock:
            if not self.sessions:
                return "NONE"
            return ",".join(f"PID:{pid}" for pid in self.sessions.keys())

    def handle_client(self, client_socket: socket.socket):
        """Handle a client connection."""

        try:
            data = client_socket.recv(1024).decode('utf-8').strip()
            if not data:
                return

            parts = data.split()
            cmd = parts[0].upper()

            if cmd == "START" and len(parts) >= 3:
                if not self.bpftrace_ready:
                    response = "ERROR bpftrace not ready"
                else:
                    pid = int(parts[1])
                    uuid = parts[2]
                    ok, msg = self.start_trace(pid, uuid)
                    response = f"OK {msg}" if ok else f"ERROR {msg}"

            elif cmd == "STOP" and len(parts) >= 2:
                pid = int(parts[1])
                ok, msg = self.stop_trace(pid)
                response = f"OK {msg}" if ok else f"ERROR {msg}"

            elif cmd == "STATUS" and len(parts) >= 2:
                pid = int(parts[1])
                ok, msg = self.get_status(pid)
                response = msg

            elif cmd == "LIST":
                response = self.list_sessions()

            elif cmd == "SHUTDOWN":
                self.running = False
                response = "OK Shutting down"

            else:
                response = f"ERROR Unknown command: {data}"

            client_socket.send(response.encode('utf-8'))

        except Exception as e:
            log.error(f"Error handling client: {e}")
            try:
                client_socket.send(f"ERROR {e}".encode('utf-8'))
            except:
                pass
        finally:
            client_socket.close()

    def cleanup(self):
        """Stop all tracing sessions and bpftrace."""

        with self.lock:
            for pid, session in list(self.sessions.items()):
                log.info(f"Stopping trace for PID {pid}")
                session.close()
            self.sessions.clear()

        self.stop_global_bpftrace()

    def run(self):
        """Run the daemon."""

        # Start global bpftrace first
        if not self.start_global_bpftrace():
            log.error("Failed to start global bpftrace")
            sys.exit(1)

        # Remove stale socket
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)

        # Create Unix socket
        self.server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server_socket.bind(self.socket_path)
        self.server_socket.listen(10)
        self.server_socket.settimeout(1.0)

        # Make socket accessible to postgres user
        os.chmod(self.socket_path, 0o666)

        log.info(f"pg_10046d started, listening on {self.socket_path}")
        log.info(f"Trace directory: {self.trace_dir}")

        try:
            while self.running:
                try:
                    client_socket, _ = self.server_socket.accept()
                    # Handle each client in a thread
                    thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                    thread.daemon = True
                    thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        log.error(f"Error accepting connection: {e}")
        finally:
            self.cleanup()
            self.server_socket.close()
            if os.path.exists(self.socket_path):
                os.unlink(self.socket_path)
            log.info("pg_10046d stopped")


def main():
    parser = argparse.ArgumentParser(description="pg_10046 eBPF Trace Daemon")
    parser.add_argument("--socket", default=DEFAULT_SOCKET, help="Unix socket path")
    parser.add_argument("--trace-dir", default=DEFAULT_TRACE_DIR, help="Trace file directory")
    parser.add_argument("--postgres", default=POSTGRES_PATH, help="PostgreSQL binary path")
    parser.add_argument("--foreground", "-f", action="store_true", help="Run in foreground")
    args = parser.parse_args()

    # Must run as root
    if os.geteuid() != 0:
        print("Error: pg_10046d must run as root", file=sys.stderr)
        sys.exit(1)

    # Check bpftrace exists
    if not os.path.exists(BPFTRACE_PATH):
        print(f"Error: bpftrace not found at {BPFTRACE_PATH}", file=sys.stderr)
        sys.exit(1)

    daemon = TraceDaemon(args.socket, args.trace_dir, args.postgres)

    # Handle signals
    def signal_handler(sig, frame):
        log.info("Received shutdown signal")
        daemon.running = False

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    daemon.run()


if __name__ == "__main__":
    main()
