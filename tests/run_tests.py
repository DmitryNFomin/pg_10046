#!/usr/bin/env python3
"""
pg_10046 Test Runner

Main entry point for running all pg_10046 tests.

Usage:
    python run_tests.py                    # Run all tests
    python run_tests.py -v                 # Verbose output
    python run_tests.py test_simple        # Run specific test module
    python run_tests.py -k "node"          # Run tests matching pattern
    python run_tests.py --list             # List available tests
    python run_tests.py --validate FILE    # Validate a trace file

Environment variables:
    PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSWORD - PostgreSQL connection
    PG10046_TRACE_DIR - Directory for trace files (default: /tmp)
"""

import sys
import os
import argparse
import unittest
from pathlib import Path

# Add tests directory to path
sys.path.insert(0, os.path.dirname(__file__))


def discover_tests(pattern: str = None) -> unittest.TestSuite:
    """Discover all test modules."""
    loader = unittest.TestLoader()

    if pattern:
        # Filter by pattern
        suite = loader.discover(
            start_dir=os.path.dirname(__file__),
            pattern=f"*{pattern}*.py",
            top_level_dir=os.path.dirname(__file__)
        )
    else:
        # All tests
        suite = loader.discover(
            start_dir=os.path.dirname(__file__),
            pattern="test_*.py",
            top_level_dir=os.path.dirname(__file__)
        )

    return suite


def list_tests(suite: unittest.TestSuite, indent: int = 0) -> list:
    """List all test cases in a suite."""
    tests = []
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            tests.extend(list_tests(test, indent))
        else:
            tests.append(str(test))
    return tests


def validate_trace_file(path: str) -> int:
    """Validate a single trace file and print results."""
    from lib.trace_validator import TraceValidator
    from lib.assertions import parse_trace, assert_basic_trace_correctness

    print(f"Validating: {path}")
    print("-" * 60)

    try:
        # Run validation
        validator = TraceValidator(path)
        result = validator.validate()

        # Print summary
        print(f"Valid: {result.is_valid}")
        print(f"Queries: {result.stats.get('query_count', 0)}")
        print(f"Events: {result.stats.get('event_count', 0)}")
        print(f"Nodes: {result.stats.get('node_count', 0)}")

        if result.errors:
            print(f"\nErrors ({len(result.errors)}):")
            for err in result.errors:
                print(f"  [{err.error_type}] Line {err.line_num}: {err.message}")

        if result.warnings:
            print(f"\nWarnings ({len(result.warnings)}):")
            for warn in result.warnings[:10]:  # Limit warnings shown
                print(f"  [{warn.error_type}] Line {warn.line_num}: {warn.message}")
            if len(result.warnings) > 10:
                print(f"  ... and {len(result.warnings) - 10} more")

        # Try full assertion check
        print("\nRunning assertion checks...")
        try:
            trace = assert_basic_trace_correctness(path)
            print("All assertions passed!")
        except AssertionError as e:
            print(f"Assertion failed: {e}")
            return 1

        return 0 if result.is_valid else 1

    except Exception as e:
        print(f"Error: {e}")
        return 1


def check_prerequisites() -> bool:
    """Check that prerequisites are met."""
    errors = []

    # Check psycopg2
    try:
        import psycopg2
    except ImportError:
        errors.append("psycopg2 not installed. Run: pip install psycopg2-binary")

    # Check PostgreSQL connection
    try:
        from lib.pg_harness import PgHarness, PgConfig
        config = PgConfig.from_env()
        harness = PgHarness(config)
        conn = harness.new_connection()

        # Check extension is loaded
        result = conn.execute("""
            SELECT EXISTS(
                SELECT 1 FROM pg_proc
                WHERE proname = 'enable_trace'
                AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'trace_10046')
            ) AS ext_loaded
        """)

        if not result.rows[0]['ext_loaded']:
            errors.append("pg_10046 extension not loaded. Add to shared_preload_libraries and restart.")

        conn.close()
        harness.cleanup()

    except Exception as e:
        errors.append(f"Cannot connect to PostgreSQL: {e}")

    if errors:
        print("Prerequisites check failed:")
        for err in errors:
            print(f"  - {err}")
        return False

    print("Prerequisites OK")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="pg_10046 Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument(
        "pattern",
        nargs="?",
        default=None,
        help="Test pattern to match (e.g., 'simple', 'node')"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="count",
        default=1,
        help="Increase verbosity (can use -vv for more)"
    )
    parser.add_argument(
        "-k", "--keyword",
        help="Only run tests matching keyword"
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available tests without running them"
    )
    parser.add_argument(
        "--validate",
        metavar="FILE",
        help="Validate a trace file"
    )
    parser.add_argument(
        "--skip-prereq",
        action="store_true",
        help="Skip prerequisite check"
    )
    parser.add_argument(
        "-f", "--failfast",
        action="store_true",
        help="Stop on first failure"
    )
    parser.add_argument(
        "--no-cleanup",
        action="store_true",
        help="Don't clean up trace files after tests"
    )

    args = parser.parse_args()

    # Handle trace validation mode
    if args.validate:
        return validate_trace_file(args.validate)

    # Check prerequisites
    if not args.skip_prereq and not args.list:
        if not check_prerequisites():
            return 1
        print()

    # Discover tests
    suite = discover_tests(args.pattern)

    # List mode
    if args.list:
        tests = list_tests(suite)
        print(f"Available tests ({len(tests)}):")
        for test in sorted(tests):
            print(f"  {test}")
        return 0

    # Filter by keyword if specified
    if args.keyword:
        filtered_suite = unittest.TestSuite()
        for test in list_tests(suite):
            if args.keyword.lower() in test.lower():
                # Re-discover just this test
                parts = test.split()
                if parts:
                    test_name = parts[0]
                    module, cls, method = test_name.rsplit('.', 2)
                    try:
                        loader = unittest.TestLoader()
                        filtered_suite.addTest(
                            loader.loadTestsFromName(f"{module}.{cls}.{method}")
                        )
                    except Exception:
                        pass
        suite = filtered_suite

    # Count tests
    test_count = suite.countTestCases()
    if test_count == 0:
        print("No tests found matching criteria")
        return 1

    print(f"Running {test_count} tests...")
    print("=" * 60)

    # Run tests
    runner = unittest.TextTestRunner(
        verbosity=args.verbose,
        failfast=args.failfast,
    )
    result = runner.run(suite)

    # Summary
    print()
    print("=" * 60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")

    if result.wasSuccessful():
        print("\nAll tests passed!")
        return 0
    else:
        print("\nSome tests failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main())
