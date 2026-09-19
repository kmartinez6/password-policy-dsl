"""Command-line entry point: `pwpolicy check policy.txt "candidate password"`.
Also `pwpolicy list policy.txt` to print the policy names in a file.

Kept thin on purpose -- argument handling and exit codes only. All of the
actual work happens in parser.py and evaluate.py, since those need to be
usable as a library independent of any CLI.

Exit codes for `check`: 0 the password satisfies the policy, 1 it
doesn't, 2 the policy file or arguments couldn't even be evaluated
(bad path, parse error, unknown rule name). `list` exits 0 unless the
file couldn't be read or parsed, in which case it's also 2.
"""

import argparse
import sys

from .errors import PolicyError
from .evaluate import evaluate
from .parser import parse_all


def _select_policy(policies, name, policy_file, err):
    if name is not None:
        for policy in policies:
            if policy.name == name:
                return policy, None
        available = ", ".join(repr(p.name) for p in policies)
        print(
            f"pwpolicy: no policy named {name!r} in {policy_file!r} "
            f"(available: {available})",
            file=err,
        )
        return None, 2

    if len(policies) == 1:
        return policies[0], None

    available = ", ".join(repr(p.name) for p in policies)
    print(
        f"pwpolicy: {policy_file!r} defines multiple policies ({available}); "
        "use --policy NAME to pick one",
        file=err,
    )
    return None, 2


def _load_policies(policy_file, err):
    try:
        with open(policy_file, "r", encoding="utf-8") as f:
            source = f.read()
    except OSError as exc:
        print(f"pwpolicy: can't read {policy_file!r}: {exc.strerror}", file=err)
        return None, 2

    try:
        return parse_all(source), None
    except PolicyError as exc:
        print(f"pwpolicy: {exc}", file=err)
        return None, 2


def _cmd_list(args, out, err):
    policies, error_code = _load_policies(args.policy_file, err)
    if policies is None:
        return error_code

    for policy in policies:
        print(policy.name, file=out)
    return 0


def _cmd_check(args, out, err):
    policies, error_code = _load_policies(args.policy_file, err)
    if policies is None:
        return error_code

    policy, error_code = _select_policy(policies, args.policy, args.policy_file, err)
    if policy is None:
        return error_code

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
    check.add_argument(
        "--policy", metavar="NAME", default=None,
        help="name of the policy to check against, "
             "required if the file defines more than one",
    )
    check.set_defaults(func=_cmd_check)

    list_cmd = subparsers.add_parser(
        "list", help="print the policy names defined in a file"
    )
    list_cmd.add_argument("policy_file", help="path to a policy source file")
    list_cmd.set_defaults(func=_cmd_list)

    return parser


def main(argv=None, out=sys.stdout, err=sys.stderr):
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args, out, err)


if __name__ == "__main__":
    sys.exit(main())
