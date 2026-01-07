#!/bin/bash
#
# pg_10046_ebpf.sh - Start/stop eBPF IO tracing for PostgreSQL backend
#
# Usage:
#   pg_10046_ebpf.sh start <pid> [trace_uuid] [trace_dir]
#   pg_10046_ebpf.sh stop <pid>
#   pg_10046_ebpf.sh status <pid>
#
# Trace files are written to:
#   <trace_dir>/pg_10046_io_<pid>_<timestamp>.trc
#
# The trace_uuid is used for correlation with extension trace files.
# If not provided, a new UUID is generated.
#

set -e

DEFAULT_TRACE_DIR="/tmp"
PID_FILE_DIR="/tmp"

usage() {
    echo "Usage: $0 {start|stop|status} <pid> [trace_uuid] [trace_dir]"
    echo ""
    echo "Commands:"
    echo "  start <pid> [uuid] [dir]  Start IO tracing for PostgreSQL backend PID"
    echo "  stop <pid>                Stop IO tracing for backend PID"
    echo "  status <pid>              Check if tracing is active for PID"
    echo ""
    echo "Arguments:"
    echo "  pid         PostgreSQL backend process ID"
    echo "  uuid        Trace UUID from extension (for correlation)"
    echo "  dir         Trace directory (default: /tmp)"
    echo ""
    echo "Environment:"
    echo "  PG_10046_TRACE_DIR       Default trace directory"
    exit 1
}

generate_uuid() {
    # Generate UUID v4 using /dev/urandom
    local r1=$(od -An -N4 -tx4 /dev/urandom | tr -d ' ')
    local r2=$(od -An -N4 -tx4 /dev/urandom | tr -d ' ')
    local r3=$(od -An -N4 -tx4 /dev/urandom | tr -d ' ')
    local r4=$(od -An -N4 -tx4 /dev/urandom | tr -d ' ')
    echo "${r1:0:8}-${r2:0:4}-4${r2:5:3}-$((8 + RANDOM % 4))${r3:1:3}-${r3:4:4}${r4:0:8}"
}

start_trace() {
    local pid=$1
    local trace_uuid=${2:-$(generate_uuid)}
    local trace_dir=${3:-${PG_10046_TRACE_DIR:-$DEFAULT_TRACE_DIR}}

    # Verify PID is a postgres process
    if ! ps -p "$pid" -o comm= 2>/dev/null | grep -q postgres; then
        echo "Error: PID $pid is not a postgres process"
        exit 1
    fi

    # Check if already tracing
    local pid_file="${PID_FILE_DIR}/pg_10046_ebpf_${pid}.pid"
    if [[ -f "$pid_file" ]]; then
        local bpf_pid=$(cat "$pid_file")
        if kill -0 "$bpf_pid" 2>/dev/null; then
            echo "Error: Already tracing PID $pid (bpftrace PID: $bpf_pid)"
            exit 1
        fi
        rm -f "$pid_file"
    fi

    # Generate trace_id: <pid>_<timestamp>
    local timestamp=$(date +%Y%m%d%H%M%S)
    local trace_id="${pid}_${timestamp}"
    local trace_file="${trace_dir}/pg_10046_io_${trace_id}.trc"

    echo "Starting IO trace for PostgreSQL backend"
    echo "  PID:        $pid"
    echo "  TRACE_ID:   $trace_id"
    echo "  TRACE_UUID: $trace_uuid"
    echo "  Trace file: $trace_file"

    # Create bpftrace script with PID filter
    local tmp_script=$(mktemp /tmp/pg_trace_io_XXXXXX.bt)

    cat > "$tmp_script" << 'BPFTRACE_SCRIPT'
#!/usr/bin/env bpftrace
/*
 * pg_10046 IO Tracer - PID-specific
 */

#define RELSEG_SIZE 131072

BEGIN {
    printf("# PG_10046 IO TRACE\n");
    printf("# TRACE_ID: %s\n", str($2));
    printf("# TRACE_UUID: %s\n", str($3));
    printf("# PID: %d\n", $1);
    printf("# START_TIME: %lu\n", nsecs);
    printf("# FORMAT: ts,IO_READ|IO_WRITE,spc,db,rel,fork,seg,blk,ela_us\n");
    printf("#\n");
}

uprobe:/usr/pgsql-13/bin/postgres:mdread /pid == $1/ {
    @rd_start[tid] = nsecs;
    @rd_spc[tid] = *(uint32*)(arg0 + 0);
    @rd_db[tid]  = *(uint32*)(arg0 + 4);
    @rd_rel[tid] = *(uint32*)(arg0 + 8);
    @rd_fork[tid] = arg1;
    @rd_blk[tid] = arg2;
    @rd_seg[tid] = arg2 / RELSEG_SIZE;
}

uretprobe:/usr/pgsql-13/bin/postgres:mdread /@rd_start[tid]/ {
    $ela = (nsecs - @rd_start[tid]) / 1000;
    printf("%lu,IO_READ,%u,%u,%u,%u,%u,%u,%lu\n",
           nsecs / 1000,
           @rd_spc[tid], @rd_db[tid], @rd_rel[tid],
           @rd_fork[tid], @rd_seg[tid], @rd_blk[tid], $ela);

    delete(@rd_start[tid]);
    delete(@rd_spc[tid]);
    delete(@rd_db[tid]);
    delete(@rd_rel[tid]);
    delete(@rd_fork[tid]);
    delete(@rd_blk[tid]);
    delete(@rd_seg[tid]);
}

uprobe:/usr/pgsql-13/bin/postgres:mdwrite /pid == $1/ {
    @wr_start[tid] = nsecs;
    @wr_spc[tid] = *(uint32*)(arg0 + 0);
    @wr_db[tid]  = *(uint32*)(arg0 + 4);
    @wr_rel[tid] = *(uint32*)(arg0 + 8);
    @wr_fork[tid] = arg1;
    @wr_blk[tid] = arg2;
    @wr_seg[tid] = arg2 / RELSEG_SIZE;
}

uretprobe:/usr/pgsql-13/bin/postgres:mdwrite /@wr_start[tid]/ {
    $ela = (nsecs - @wr_start[tid]) / 1000;
    printf("%lu,IO_WRITE,%u,%u,%u,%u,%u,%u,%lu\n",
           nsecs / 1000,
           @wr_spc[tid], @wr_db[tid], @wr_rel[tid],
           @wr_fork[tid], @wr_seg[tid], @wr_blk[tid], $ela);

    delete(@wr_start[tid]);
    delete(@wr_spc[tid]);
    delete(@wr_db[tid]);
    delete(@wr_rel[tid]);
    delete(@wr_fork[tid]);
    delete(@wr_blk[tid]);
    delete(@wr_seg[tid]);
}

END {
    printf("\n# END_TIME: %lu\n", nsecs);
}
BPFTRACE_SCRIPT

    # Start bpftrace in background
    sudo bpftrace "$tmp_script" "$pid" "$trace_id" "$trace_uuid" > "$trace_file" 2>&1 &
    local bpf_pid=$!

    # Wait a moment to check if it started successfully
    sleep 2
    if ! kill -0 "$bpf_pid" 2>/dev/null; then
        echo "Error: bpftrace failed to start. Check trace file for errors:"
        head -20 "$trace_file"
        rm -f "$tmp_script"
        exit 1
    fi

    # Save state for later stop
    echo "$bpf_pid" > "$pid_file"
    echo "$tmp_script" > "${pid_file}.script"
    echo "$trace_file" > "${pid_file}.trace"
    echo "$trace_uuid" > "${pid_file}.uuid"

    echo ""
    echo "Started bpftrace (PID: $bpf_pid)"
    echo "To stop: $0 stop $pid"
}

stop_trace() {
    local pid=$1
    local pid_file="${PID_FILE_DIR}/pg_10046_ebpf_${pid}.pid"

    if [[ ! -f "$pid_file" ]]; then
        echo "Error: No active trace for PID $pid"
        exit 1
    fi

    local bpf_pid=$(cat "$pid_file")
    local script_file=$(cat "${pid_file}.script" 2>/dev/null)
    local trace_file=$(cat "${pid_file}.trace" 2>/dev/null)
    local trace_uuid=$(cat "${pid_file}.uuid" 2>/dev/null)

    echo "Stopping IO trace for PostgreSQL backend PID $pid"

    if kill -0 "$bpf_pid" 2>/dev/null; then
        sudo kill -INT "$bpf_pid" 2>/dev/null || true
        sleep 1
        # Force kill if still running
        if kill -0 "$bpf_pid" 2>/dev/null; then
            sudo kill -9 "$bpf_pid" 2>/dev/null || true
        fi
        echo "Stopped bpftrace (PID: $bpf_pid)"
    else
        echo "bpftrace already stopped"
    fi

    # Cleanup
    rm -f "$pid_file" "${pid_file}.script" "${pid_file}.trace" "${pid_file}.uuid"
    [[ -n "$script_file" ]] && rm -f "$script_file"

    if [[ -n "$trace_file" && -f "$trace_file" ]]; then
        local lines=$(wc -l < "$trace_file")
        local io_count=$(grep -c ",IO_" "$trace_file" 2>/dev/null || echo 0)
        echo ""
        echo "Trace file: $trace_file"
        echo "  Lines: $lines"
        echo "  IO events: $io_count"
        echo "  UUID: $trace_uuid"
    fi
}

status_trace() {
    local pid=$1
    local pid_file="${PID_FILE_DIR}/pg_10046_ebpf_${pid}.pid"

    if [[ ! -f "$pid_file" ]]; then
        echo "No active trace for PID $pid"
        exit 1
    fi

    local bpf_pid=$(cat "$pid_file")
    local trace_file=$(cat "${pid_file}.trace" 2>/dev/null)
    local trace_uuid=$(cat "${pid_file}.uuid" 2>/dev/null)

    if kill -0 "$bpf_pid" 2>/dev/null; then
        echo "Active trace for PID $pid"
        echo "  bpftrace PID: $bpf_pid"
        echo "  Trace file:   $trace_file"
        echo "  TRACE_UUID:   $trace_uuid"
        if [[ -f "$trace_file" ]]; then
            local lines=$(wc -l < "$trace_file")
            local io_count=$(grep -c ",IO_" "$trace_file" 2>/dev/null || echo 0)
            echo "  Lines:        $lines"
            echo "  IO events:    $io_count"
        fi
    else
        echo "Trace was active but bpftrace has stopped"
        rm -f "$pid_file" "${pid_file}.script" "${pid_file}.trace" "${pid_file}.uuid"
    fi
}

# Main
case "${1:-}" in
    start)
        [[ -z "${2:-}" ]] && usage
        start_trace "$2" "${3:-}" "${4:-}"
        ;;
    stop)
        [[ -z "${2:-}" ]] && usage
        stop_trace "$2"
        ;;
    status)
        [[ -z "${2:-}" ]] && usage
        status_trace "$2"
        ;;
    *)
        usage
        ;;
esac
