"""
test_cli.py — Unit tests for cli.py's argument parsing and --deep resolution.
"""

from macskillet.cli import _build_parser, _resolve_deep_limit


def _parse(argv):
    return _build_parser().parse_args(argv)


def test_deep_alone_gives_default_limit():
    args = _parse(["App.app", "--deep"])
    assert _resolve_deep_limit(args) == 10


def test_deep_limit_alone_implies_deep():
    args = _parse(["App.app", "--deep-limit", "25"])
    assert _resolve_deep_limit(args) == 25


def test_deep_and_deep_limit_together():
    args = _parse(["App.app", "--deep", "--deep-limit", "3"])
    assert _resolve_deep_limit(args) == 3


def test_neither_flag_disables_deep_scan():
    args = _parse(["App.app"])
    assert _resolve_deep_limit(args) is None
