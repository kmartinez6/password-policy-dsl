"""Pretty printer: turns a Policy AST back into canonical source text.

Running parse() then format_policy() twice should be a no-op on the second
pass — the point is to give a policy file one normalized shape (quoting,
spacing, list layout) regardless of how the original author wrote it.
"""


def format_policy(policy):
    lines = [f'policy "{policy.name}" {{']
    for rule in policy.rules:
        lines.append(f"  {rule.name}: {_format_value(rule.value)}")
    lines.append("}")
    return "\n".join(lines) + "\n"


def _format_value(value):
    if value.kind == "number":
        return str(value.data)
    if value.kind == "ident":
        return value.data
    if value.kind == "string":
        return f'"{_escape(value.data)}"'
    if value.kind == "list":
        return "[" + ", ".join(_format_value(item) for item in value.data) + "]"
    raise ValueError(f"unknown value kind {value.kind!r}")


def _escape(text):
    return text.replace("\\", "\\\\").replace('"', '\\"')
