# Makefile for pg_10046 extension

MODULES = pg_10046
EXTENSION = pg_10046
DATA = pg_10046--1.0.sql
PGFILEDESC = "pg_10046 - Oracle 10046-style SQL tracing"

# Use pg_config for build settings
PG_CONFIG ?= pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
