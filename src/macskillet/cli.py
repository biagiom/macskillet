"""
cli.py — the ``macskillet`` command.

One entry point over both pipelines. The backend (who extracts features and
answers tool calls) and the mode (how the agent reasons) are independent
choices::

    macskillet App.app                          # auto backend, react mode
    macskillet App.app --backend detector       # force cross-platform
    macskillet App.app --mode hierarchical      # cheaper on benign-heavy sets
    macskillet App.app --features-only --pretty # extraction only, no API call
    macskillet --batch samples/ -o results.jsonl
    macskillet --list-backends
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from macskillet import DEFAULT_CLAUDE_MODEL, __version__
from macskillet.backends import BackendUnavailable, available_backends, select_backend

MODES = ("react", "one_shot", "hierarchical", "react_thinking")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="macskillet",
        description="Agentic static analysis and malware classification for macOS.",
    )
    parser.add_argument("sample", nargs="?", help="path to a .app bundle or Mach-O binary")
    parser.add_argument("--batch", metavar="DIR", help="analyze every sample under DIR")
    parser.add_argument("-o", "--output", help="write JSON/JSONL here instead of stdout")
    parser.add_argument("--pretty", action="store_true", help="indent JSON output")
    parser.add_argument("--version", action="version", version=f"macskillet {__version__}")

    group = parser.add_argument_group("analysis")
    group.add_argument(
        "--backend",
        choices=["auto", "native", "detector"],
        default="auto",
        help="feature-extraction pipeline (default: auto — native on macOS, detector elsewhere)",
    )
    group.add_argument("--mode", choices=MODES, default="react", help="agentic mode (default: react)")
    group.add_argument(
        "--features-only",
        action="store_true",
        help="extract features and stop — no model call, no API key needed",
    )
    group.add_argument("--list-backends", action="store_true", help="show backend availability and exit")

    inference = parser.add_argument_group("inference")
    inference.add_argument("--ollama", action="store_true", help="local LLM via Ollama instead of the Claude API")
    inference.add_argument("--apple", action="store_true", help="on-device Apple Foundation Models (macOS 26+)")
    inference.add_argument(
        "--model",
        default=None,
        help=f"model id (default: {DEFAULT_CLAUDE_MODEL}, or qwen2.5:14b with --ollama)",
    )
    return parser


def _list_backends() -> int:
    from macskillet.backends import DETECTOR, NATIVE

    for backend in (NATIVE, DETECTOR):
        reason = backend.unavailable_reason()
        status = "available" if reason is None else f"unavailable — {reason}"
        print(f"{backend.name:9s} {status}")
        print(f"          {backend.description}")
    return 0 if available_backends() else 1


def _classify(features: dict, args, backend) -> dict:
    """Route to the requested inference path."""
    if args.apple:
        if args.mode != "react":
            print(f"[!] --apple supports react only; ignoring --mode {args.mode}", file=sys.stderr)
        from macskillet.native.agent_loop_foundation import run_agent_foundation

        return run_agent_foundation(features)

    if args.ollama:
        if args.mode != "react":
            print(f"[!] --ollama supports react only; ignoring --mode {args.mode}", file=sys.stderr)
        from macskillet.native.agent_loop_local import run_agent_local

        return run_agent_local(features, model=args.model or "qwen2.5:14b")

    from macskillet.native.agent_modes import run_mode

    return run_mode(features, mode=args.mode, backend=backend,
                    model=args.model or DEFAULT_CLAUDE_MODEL)


def _emit(payload, args) -> None:
    text = json.dumps(payload, indent=2 if args.pretty else None, default=str)
    if args.output:
        with open(args.output, "w") as fh:
            fh.write(text)
    else:
        print(text)


def _iter_samples(root: str, backend):
    """Yield .app bundles and Mach-O binaries under ``root``.

    A bundle is yielded whole and not descended into — analyzing every dylib
    inside an app separately would multiply cost without adding signal.
    """
    from macskillet.machopy.macho_analyzer import is_macho

    for dirpath, dirnames, filenames in os.walk(root):
        for name in list(dirnames):
            if name.endswith(".app"):
                yield os.path.join(dirpath, name)
                dirnames.remove(name)
        for name in filenames:
            path = os.path.join(dirpath, name)
            if is_macho(path):
                yield path


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.list_backends:
        return _list_backends()

    if not args.sample and not args.batch:
        parser.print_help()
        return 1

    if args.ollama and args.apple:
        print("[!] --ollama and --apple are mutually exclusive.", file=sys.stderr)
        return 1

    needs_api_key = not (args.features_only or args.ollama or args.apple)
    if needs_api_key and not os.environ.get("ANTHROPIC_API_KEY"):
        print(
            "[!] ANTHROPIC_API_KEY not set. Use --features-only to skip inference, "
            "or --ollama / --apple for local models.",
            file=sys.stderr,
        )
        return 1

    try:
        backend = select_backend(None if args.backend == "auto" else args.backend)
    except BackendUnavailable as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    print(f"[*] Backend: {backend.name}", file=sys.stderr)

    if args.sample:
        features = backend.extract(args.sample)
        if features.get("errors"):
            print(f"[!] {features['errors']}", file=sys.stderr)
        if args.features_only:
            _emit(features, args)
            return 0

        report = _classify(features, args, backend)
        report["clickfix_detection"] = features.get("clickfix")
        report["obfuscation_detection"] = features.get("obfuscation")

        from macskillet.native.classify_bundle_native import print_report

        print_report(report)
        _emit(report, args)
        return 0

    # -- batch ------------------------------------------------------------
    if not args.output:
        print("[!] --batch requires -o", file=sys.stderr)
        return 1

    samples = list(_iter_samples(args.batch, backend))
    print(f"[*] {len(samples)} samples found", file=sys.stderr)
    failures = 0

    with open(args.output, "w") as fh:
        for index, path in enumerate(samples, start=1):
            print(f"\n[{index}/{len(samples)}] {path}", file=sys.stderr)
            try:
                features = backend.extract(path)
                if args.features_only:
                    record = features
                else:
                    record = _classify(features, args, backend)
                    record["clickfix_detection"] = features.get("clickfix")
                    record["obfuscation_detection"] = features.get("obfuscation")
            except Exception as exc:
                failures += 1
                print(f"[!] {type(exc).__name__}: {exc}", file=sys.stderr)
                record = {"sample": {"path": path}, "error": f"{type(exc).__name__}: {exc}"}
            fh.write(json.dumps(record, default=str) + "\n")
            fh.flush()

    if failures:
        print(f"[!] {failures}/{len(samples)} samples failed", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
