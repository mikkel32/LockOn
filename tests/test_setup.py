import sys
from setup import run_tests, show_test_results
from src.utils.helpers import console


def test_run_tests_single():
    out, code = run_tests(
        ["tests/test_debug_server.py::test_debug_server_exits_gracefully_without_debugpy"],
        python=sys.executable,
        coverage=True,
    )
    assert code == 0
    assert "1 passed" in out
    assert "tests coverage" in out


def test_show_test_results_capture():
    with console.capture() as capture:
        show_test_results(
            ["tests/test_debug_server.py::test_debug_server_exits_gracefully_without_debugpy"],
            python=sys.executable,
            coverage=True,
        )
    text = capture.get()
    assert "1 passed" in text


def test_run_tests_parallel():
    out, code = run_tests(
        ["tests/test_debug_server.py::test_debug_server_exits_gracefully_without_debugpy"],
        python=sys.executable,
        parallel=True,
    )
    assert code == 0
    assert "1 passed" in out
    assert "bringing up nodes" in out.lower()


def test_show_test_results_parallel_capture():
    with console.capture() as capture:
        show_test_results(
            ["tests/test_debug_server.py::test_debug_server_exits_gracefully_without_debugpy"],
            python=sys.executable,
            coverage=True,
            parallel=True,
        )
    text = capture.get()
    assert "1 passed" in text
