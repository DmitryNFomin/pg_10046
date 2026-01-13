-- pg_10046 extension SQL file
-- This extension is loaded via shared_preload_libraries or LOAD

COMMENT ON EXTENSION pg_10046 IS 'Oracle 10046-style SQL tracing for PostgreSQL';

-- Schema for trace control functions
CREATE SCHEMA IF NOT EXISTS trace_10046;

-- Enable tracing on another backend
-- The target backend will start tracing at its next query
CREATE FUNCTION trace_10046.enable_trace(target_pid integer)
RETURNS boolean
AS 'pg_10046', 'pg_10046_enable_trace'
LANGUAGE C STRICT;

COMMENT ON FUNCTION trace_10046.enable_trace(integer) IS
'Enable SQL tracing on another backend. Target will start tracing at next query.';

-- Enable tracing on another backend (with eBPF already active flag)
-- Used by pg_10046_attach CLI when it has already started eBPF externally
CREATE FUNCTION trace_10046.enable_trace_ebpf(target_pid integer)
RETURNS boolean
AS 'pg_10046', 'pg_10046_enable_trace_ebpf'
LANGUAGE C STRICT;

COMMENT ON FUNCTION trace_10046.enable_trace_ebpf(integer) IS
'Enable SQL tracing on another backend with eBPF already started externally.';

-- Disable tracing request for another backend
-- Note: only clears pending request, does not stop active tracing
CREATE FUNCTION trace_10046.disable_trace(target_pid integer)
RETURNS boolean
AS 'pg_10046', 'pg_10046_disable_trace'
LANGUAGE C STRICT;

COMMENT ON FUNCTION trace_10046.disable_trace(integer) IS
'Clear pending trace request for another backend.';
