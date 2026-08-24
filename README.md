# pwpolicy

Password policies end up scattered across a codebase as ad hoc checks —
a regex here, an `if len(password) < 8` there, a config value with no
documented shape. `pwpolicy` is a small language for writing those
policies down as data, plus a parser and pretty printer for it.

The parser is the part meant to be actually good: when a policy file is
malformed, the error names the line and column and shows the offending
text, instead of a bare "syntax error".

This is the language and its tooling. It does not yet check passwords
against a parsed policy — that's the next piece (see Roadmap).

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
rule names (which point back at the first definition's line), and
unexpected characters — every `PolicyError` carries `.line`, `.column`,
and `.length` in addition to the rendered message, so callers can build
their own reporting (an editor gutter marker, a CI annotation) instead
of parsing the text back out.

## Layout

- `src/pwpolicy/parser.py` — lexer, AST, and recursive-descent parser
- `src/pwpolicy/printer.py` — canonical pretty printer
- `src/pwpolicy/errors.py` — `PolicyError`, with source-line rendering

## Status

Early skeleton: the language, parser, and printer work; nothing yet
evaluates a password against a parsed policy. See Roadmap.

## Roadmap

- Evaluate a password string against a parsed `Policy` and report which
  rules failed
- Ship a starter set of rule names (`min_length`, `require`, `forbid_repeat`,
  `forbid_sequence`, `deny_substrings`, ...) with documented semantics
- Validate rule values at parse time (e.g. `min_length` must be a
  positive number) instead of leaving that to the evaluator
- Test suite covering the lexer, parser error messages, and printer
  round-tripping
- Small CLI: `pwpolicy check policy.txt "candidate password"`
- Support multiple named policies per file
