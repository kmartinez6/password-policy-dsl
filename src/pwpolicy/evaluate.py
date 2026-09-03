"""Evaluate a password against a parsed Policy.

Rule semantics live here, one function per rule name. RULES below is the
full starter set this module understands; each check function's
docstring is the spec for that rule name.

parser.py's validate.py already rejects malformed values (a
`min_length: "oops"` policy fails to parse), but the checks below still
validate their own value's shape and raise ValueError on a bad fit, in
case evaluate() is ever called with a Policy that wasn't built by
parse() -- e.g. one assembled by hand from Rule/Value directly.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Violation:
    rule: str
    message: str


@dataclass(frozen=True)
class EvaluationResult:
    violations: list

    @property
    def ok(self):
        return not self.violations


_CATEGORIES = {
    "upper": lambda c: c.isupper(),
    "lower": lambda c: c.islower(),
    "digit": lambda c: c.isdigit(),
    "symbol": lambda c: not c.isalnum() and not c.isspace(),
}


def _expect_number(rule_name, value):
    if value.kind != "number":
        raise ValueError(f"rule {rule_name!r} expects a number, got a {value.kind}")
    return value.data


def _expect_list_of_idents(rule_name, value):
    if value.kind != "list" or any(item.kind != "ident" for item in value.data):
        raise ValueError(f"rule {rule_name!r} expects a list of identifiers")
    return [item.data for item in value.data]


def _expect_list_of_strings(rule_name, value):
    if value.kind != "list" or any(item.kind != "string" for item in value.data):
        raise ValueError(f"rule {rule_name!r} expects a list of strings")
    return [item.data for item in value.data]


def _check_min_length(value, password):
    """min_length: NUMBER -- password must be at least this many characters."""
    n = _expect_number("min_length", value)
    if len(password) < n:
        return f"must be at least {n} characters long (got {len(password)})"


def _check_max_length(value, password):
    """max_length: NUMBER -- password must be at most this many characters."""
    n = _expect_number("max_length", value)
    if len(password) > n:
        return f"must be at most {n} characters long (got {len(password)})"


def _check_require(value, password):
    """require: [CATEGORY, ...] -- password must contain at least one
    character from each named category. Categories: upper, lower, digit,
    symbol (symbol is anything that is not alphanumeric and not whitespace).
    """
    names = _expect_list_of_idents("require", value)
    missing = []
    for name in names:
        test = _CATEGORIES.get(name)
        if test is None:
            raise ValueError(
                f"rule 'require' names unknown character category {name!r} "
                f"(known: {', '.join(sorted(_CATEGORIES))})"
            )
        if not any(test(c) for c in password):
            missing.append(name)
    if missing:
        return f"must contain at least one of each: {', '.join(missing)}"


def _check_min_unique(value, password):
    """min_unique: NUMBER -- password must contain at least this many
    distinct characters (repeats of the same character only count once).
    """
    n = _expect_number("min_unique", value)
    unique = len(set(password))
    if unique < n:
        return f"must use at least {n} distinct characters (got {unique})"


def _check_forbid_repeat(value, password):
    """forbid_repeat: NUMBER -- password must not repeat the same
    character NUMBER or more times in a row (forbid_repeat: 3 rejects
    "aaa" but allows "aa").
    """
    n = _expect_number("forbid_repeat", value)
    if n < 1:
        raise ValueError("rule 'forbid_repeat' must be a positive number")
    run_char, run_len = None, 0
    for c in password:
        if c == run_char:
            run_len += 1
        else:
            run_char, run_len = c, 1
        if run_len >= n:
            return (
                f"must not repeat the same character {n} or more times in a "
                f"row (found {c!r} x{run_len})"
            )


def _check_forbid_sequence(value, password):
    """forbid_sequence: NUMBER -- password must not contain a run of
    NUMBER or more consecutive characters that ascend or descend by one
    code point each step (forbid_sequence: 3 rejects "abc" and "321").
    """
    n = _expect_number("forbid_sequence", value)
    if n < 2:
        raise ValueError("rule 'forbid_sequence' must be at least 2")
    direction, run_len = 0, 1
    for i in range(1, len(password)):
        step = ord(password[i]) - ord(password[i - 1])
        if step in (1, -1) and step == direction:
            run_len += 1
        elif step in (1, -1):
            direction, run_len = step, 2
        else:
            direction, run_len = 0, 1
        if run_len >= n:
            found = password[i - run_len + 1 : i + 1]
            return f"must not contain a run of {n} or more consecutive characters (like {found!r})"


def _check_deny_substrings(value, password):
    """deny_substrings: [STRING, ...] -- password must not contain any of
    these strings as a substring, case-insensitively.
    """
    substrings = _expect_list_of_strings("deny_substrings", value)
    lowered = password.lower()
    found = sorted(s for s in substrings if s.lower() in lowered)
    if found:
        return f"must not contain forbidden text: {', '.join(found)}"


RULES = {
    "min_length": _check_min_length,
    "max_length": _check_max_length,
    "require": _check_require,
    "min_unique": _check_min_unique,
    "forbid_repeat": _check_forbid_repeat,
    "forbid_sequence": _check_forbid_sequence,
    "deny_substrings": _check_deny_substrings,
}


def evaluate(policy, password):
    """Check password against every rule in policy.

    Returns an EvaluationResult; result.ok is True when nothing failed.
    Raises ValueError if the policy uses a rule name this module doesn't
    know, or gives a rule a value shaped wrong for it.
    """
    violations = []
    for rule in policy.rules:
        check = RULES.get(rule.name)
        if check is None:
            raise ValueError(
                f"unknown rule {rule.name!r} (known rules: {', '.join(sorted(RULES))})"
            )
        message = check(rule.value, password)
        if message is not None:
            violations.append(Violation(rule.name, message))
    return EvaluationResult(violations)
