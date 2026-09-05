# pwpolicy

Password policies end up scattered across a codebase as ad hoc checks —
a regex here, an `if len(password) < 8` there, a config value with no
documented shape. `pwpolicy` is a small language for writing those
policies down as data, plus a parser and pretty printer for it.

The parser is the part meant to be actually good: when a policy file is
malformed, the error names the line and column and shows the offending
text, instead of a bare "syntax error".

## The language

```
policy "corporate-default" {
  min_length: 12
  max_length: 128
  require: [upper, lower, digit, symbol]
  min_unique: 6
  forbid_repeat: 3
  forbid_sequence: 3
  deny_substrings: ["password", "qwerty", "letmein"]
}
```

A file holds exactly one `policy` block: a quoted name and a set of
`name: value` rules. A value is a number, a bare identifier, a quoted
string, or a `[...]` list of any of those. Rule names may not repeat
within a policy. `#` starts a line comment.

## Rules

The evaluator (`pwpolicy.evaluate`) understands this starter set. Using
any other rule name is an error.

| Rule | Value | Checks |
| --- | --- | --- |
| `min_length` | number | password is at least this many characters |
| `max_length` | number | password is at most this many characters |
| `require` | `[category, ...]` | password has at least one character from each category: `upper`, `lower`, `digit`, `symbol` (symbol = not alphanumeric, not whitespace) |
| `min_unique` | number | password has at least this many distinct characters |
| `forbid_repeat` | number | password has no run of this many or more of the same character in a row |
| `forbid_sequence` | number | password has no run of this many or more characters that ascend or descend by one code point each step (`"abc"`, `"321"`) |
| `deny_substrings` | `[string, ...]` | password contains none of these, case-insensitively |

Rule values are checked for shape as soon as they're parsed, so a
policy like `min_length: "twelve"` (a string where a number is
required) or `forbid_repeat: 0` (below the rule's minimum) fails to
parse with a located error rather than surfacing later when a password
is checked against it. An unrecognized rule name is not caught until
evaluation, since the parser has no opinion on which rule names exist.

## Usage

```python
import pwpolicy

source = '''
policy "corporate-default" {
  min_length: 12
  require: [upper, lower, digit, symbol]
}
'''

policy = pwpolicy.parse(source)
print(policy.name)              # "corporate-default"
print([r.name for r in policy.rules])  # ["min_length", "require"]

# Re-emit the policy in canonical form (consistent spacing and quoting,
# regardless of how the input was written).
print(pwpolicy.format_policy(policy))

# Check a password against the parsed policy.
result = pwpolicy.evaluate(policy, "hunter2")
if not result.ok:
    for violation in result.violations:
        print(f"{violation.rule}: {violation.message}")
```

## Errors with real locations

Given a file missing the colon after a rule name:

```
policy "corp" {
  min_length 12
}
```

```pycon
>>> pwpolicy.parse(open("bad.policy").read())
Traceback (most recent call last):
  ...
pwpolicy.errors.PolicyError: line 2, column 14: expected ':' after the rule name, found '12'
      min_length 12
                 ^^
```

The same happens for unterminated strings, unclosed braces, duplicate
rule names (which point back at the first definition's line), badly
shaped rule values, and unexpected characters — every `PolicyError`
carries `.line`, `.column`, and `.length` in addition to the rendered
message, so callers can build their own reporting (an editor gutter
marker, a CI annotation) instead of parsing the text back out.

## Layout

- `src/pwpolicy/parser.py` — lexer, AST, and recursive-descent parser
- `src/pwpolicy/validate.py` — rule value shape checks, run during parsing
- `src/pwpolicy/printer.py` — canonical pretty printer
- `src/pwpolicy/evaluate.py` — starter rule set and password evaluation
- `src/pwpolicy/errors.py` — `PolicyError`, with source-line rendering
- `tests/` — unit tests, stdlib `unittest` only

## Testing

No test runner install required — the suite is plain `unittest` and
`tests/__init__.py` puts `src/` on `sys.path` for you:

```
python -m unittest discover
```

## Status

The language, parser, printer, and a starter rule set for evaluation
all work, and are covered by tests. See Roadmap for what's left.

## Roadmap

- Small CLI: `pwpolicy check policy.txt "candidate password"`
- Support multiple named policies per file
