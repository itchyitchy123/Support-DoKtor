from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .context import InvestigationContext
from .engine import MODULES, run_investigation, run_single_module
from .models import Mode
from .render import render_case_summary, render_json, render_text
from .util import parse_time


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        context = InvestigationContext(
            domain=args.domain,
            center_time=parse_time(args.time),
            window_minutes=args.window,
            mode=_mode_from_args(args),
            root=Path(args.root),
        )
    except ValueError as exc:
        parser.error(str(exc))

    if args.command == "case-summary":
        report = run_investigation(context)
        print(render_json(report) if args.json else render_case_summary(report))
        return 0

    if args.command == "investigate":
        report = run_investigation(context)
    else:
        report = run_single_module(args.command, context)

    print(render_json(report) if args.json else render_text(report))
    if context.mode == Mode.EXECUTE:
        # Execute mode must fail closed: an empty report is not proof that an
        # action ran, and every incident must explicitly opt in to execution.
        if not report.incidents or any(
            not (incident.plan and incident.plan.execute_supported) for incident in report.incidents
        ):
            return 2
    return 0


def _build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--domain", help="Domain to focus log correlation on")
    common.add_argument("--time", help='Center time for historical reconstruction, e.g. "2026-08-26 03:17"')
    common.add_argument("--window", type=int, default=10, help="Minutes before and after --time to inspect")
    common.add_argument(
        "--root", default="/", help="Alternate filesystem root for fixtures, snapshots, or mounted servers"
    )
    common.add_argument("--json", action="store_true", help="Emit sanitized structured JSON")
    mode = common.add_mutually_exclusive_group()
    mode.add_argument("--inspect", action="store_true", help="Collect evidence only")
    mode.add_argument("--plan", action="store_true", help="Generate recovery plan without changes")
    mode.add_argument(
        "--execute",
        action="store_true",
        help="Execute approved module actions where implemented (fails closed when unsupported)",
    )

    parser = argparse.ArgumentParser(
        prog="support-doctor", description="Linux hosting diagnostic and recovery planning engine"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("investigate", parents=[common], help="Run broad hosting incident investigation")
    sub.add_parser("case-summary", parents=[common], help="Generate engineer-ready case summary")
    for name in sorted(MODULES):
        sub.add_parser(name, parents=[common], help=f"Run {name} diagnostics")
    return parser


def _mode_from_args(args: argparse.Namespace) -> Mode:
    if args.plan:
        return Mode.PLAN
    if args.execute:
        return Mode.EXECUTE
    return Mode.INSPECT


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
