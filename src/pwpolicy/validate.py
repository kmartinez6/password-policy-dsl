"""Shape checks for rule values, run once at parse time.

Before this module existed, a policy like `min_length: "twelve"` or
`forbid_repeat: 0` parsed without complaint and only blew up once you
tried to evaluate a password against it, with a ValueError instead of a
located PolicyError. These checks catch the same problems where they're
actually introduced -- in the source text -- and point at the exact
value token that's wrong.

This only checks value *shape* for rule names it recognizes. An unknown
rule name is left alone here; evaluate() is still the source of truth
for which rule names exist at all.
"""

from .errors import PolicyError

# Mirrors evaluate.py's category set. Duplicated rather than imported so
# that parsing doesn't depend on the evaluator module -- keep both in
# sync if a category is ever added or renamed.
_CATEGORY_NAMES = {"upper", "lower", "digit", "symbol"}


def _length_of(value):
    if value.kind == "number":
        return len(str(value.data))
    if value.kind == "ident":
        return len(value.data)
    if value.kind == "string":
        return len(value.data) + 2
    return 1


def _fail(source, rule_name, message, target):
    raise PolicyError(
        f"rule {rule_name!r} {message}",
        source, target.line, target.column, _length_of(target),
    )


def _check_number(source, rule_name, value):
    if value.kind != "number":
        _fail(source, rule_name, "expects a number", value)


def _check_forbid_repeat(source, rule_name, value):
    _check_number(source, rule_name, value)
    if value.data < 1:
        _fail(source, rule_name, "must be at least 1", value)


def _check_forbid_sequence(source, rule_name, value):
    _check_number(source, rule_name, value)
    if value.data < 2:
        _fail(source, rule_name, "must be at least 2", value)


def _check_require(source, rule_name, value):
    if value.kind != "list" or any(item.kind != "ident" for item in value.data):
        _fail(source, rule_name, "expects a list of identifiers", value)
    for item in value.data:
        if item.data not in _CATEGORY_NAMES:
            _fail(
                source, rule_name,
                f"names unknown character category {item.data!r} "
                f"(known: {', '.join(sorted(_CATEGORY_NAMES))})",
                item,
            )


def _check_deny_substrings(source, rule_name, value):
    if value.kind != "list" or any(item.kind != "string" for item in value.data):
        _fail(source, rule_name, "expects a list of strings", value)


_VALIDATORS = {
    "min_length": _check_number,
    "max_length": _check_number,
    "min_unique": _check_number,
    "forbid_repeat": _check_forbid_repeat,
    "forbid_sequence": _check_forbid_sequence,
    "require": _check_require,
    "deny_substrings": _check_deny_substrings,
}


def validate_rule_value(source, rule_name, value):
    """Raise PolicyError if `value` is the wrong shape for `rule_name`.

    Does nothing for rule names this module doesn't have a check for.
    """
    validator = _VALIDATORS.get(rule_name)
    if validator is not None:
        validator(source, rule_name, value)
