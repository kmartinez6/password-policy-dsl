"""Command-line entry point: `pwpolicy check policy.txt "candidate password"`.

Kept thin on purpose -- argument handling and exit codes only. All of the
actual work happens in parser.py and evaluate.py, since those need to be
usable as a library independent of any CLI.

Exit codes: 0 the password satisfies the policy, 1 it doesn't, 2 the
policy file or arguments couldn't even be evaluated (bad path, parse
error, unknown rule name).
"""

import argparse
import sys

from .errors import PolicyError
from .evaluate import evaluate
from .parser import parse


def _cmd_check(args, out, err):
    try:
        with open(args.policy_file, "r", encoding="utf-8") as f:
            source = f.read()
    except OSError as exc:
        print(f"pwpolicy: can't read {args.policy_file!r}: {exc.strerror}", file=err)
        return 2

    try:
        policy = parse(source)
    except PolicyError as exc:
        print(f"pwpolicy: {exc}", file=err)
        return 2

    try:
        result = evaluate(policy, args.password)
    except ValueError as exc:
        print(f"pwpolicy: {exc}", file=err)
        return 2

    if result.ok:
        print(f"OK: password satisfies policy {policy.name!r}", file=out)
        return 0

    print(f"FAIL: password violates policy {policy.name!r}", file=out)
    for violation in result.violations:
        print(f"  {violation.rule}: {violation.message}", file=out)
    return 1


def build_parser():
    parser = argparse.ArgumentParser(prog="pwpolicy")
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser(
        "check", help="check a candidate password against a policy file"
    )
    check.add_argument("policy_file", help="path to a policy source file")
    check.add_argument("password", help="candidate password to check")
    check.set_defaults(func=_cmd_check)

    return parser


def main(argv=None, out=sys.stdout, err=sys.stderr):
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args, out, err)


if __name__ == "__main__":
    sys.exit(main())
