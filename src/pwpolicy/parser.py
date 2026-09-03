"""Lexer, AST, and parser for the policy language.

Grammar (informal):

    policy   := "policy" STRING "{" rule* "}"
    rule     := IDENT ":" value
    value    := NUMBER | IDENT | STRING | list
    list     := "[" (value ("," value)*)? "]"

Example:

    policy "corporate-default" {
      min_length: 12
      require: [upper, lower, digit, symbol]
      forbid_repeat: 3
    }

Every token records its own line and column so that a parse failure can
point at the exact spot in the source, not just "somewhere in this file".
"""

from dataclasses import dataclass

from .errors import PolicyError
from .validate import validate_rule_value


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    line: int
    column: int


@dataclass
class Value:
    kind: str  # "number" | "ident" | "string" | "list"
    data: object  # int | str | list[Value]
    line: int
    column: int


@dataclass
class Rule:
    name: str
    value: Value
    line: int
    column: int


@dataclass
class Policy:
    name: str
    rules: list
    line: int
    column: int


_PUNCTUATION = {
    "{": "LBRACE",
    "}": "RBRACE",
    "[": "LBRACKET",
    "]": "RBRACKET",
    ":": "COLON",
    ",": "COMMA",
}


def tokenize(source):
    tokens = []
    line = 1
    col = 1
    i = 0
    n = len(source)

    def advance(count=1):
        nonlocal i, line, col
        for _ in range(count):
            if source[i] == "\n":
                line += 1
                col = 1
            else:
                col += 1
            i += 1

    while i < n:
        ch = source[i]

        if ch in " \t\r\n":
            advance()
            continue

        if ch == "#":
            while i < n and source[i] != "\n":
                advance()
            continue

        start_line, start_col = line, col

        if ch in _PUNCTUATION:
            tokens.append(Token(_PUNCTUATION[ch], ch, start_line, start_col))
            advance()
            continue

        if ch == '"':
            chars = []
            advance()
            closed = False
            while i < n:
                c = source[i]
                if c == '"':
                    advance()
                    closed = True
                    break
                if c == "\n":
                    break
                if c == "\\" and i + 1 < n and source[i + 1] in ('"', "\\"):
                    chars.append(source[i + 1])
                    advance(2)
                    continue
                chars.append(c)
                advance()
            if not closed:
                raise PolicyError(
                    "unterminated string literal (missing closing '\"')",
                    source, start_line, start_col,
                )
            tokens.append(Token("STRING", "".join(chars), start_line, start_col))
            continue

        if ch.isdigit():
            digits = []
            while i < n and source[i].isdigit():
                digits.append(source[i])
                advance()
            tokens.append(Token("NUMBER", "".join(digits), start_line, start_col))
            continue

        if ch.isalpha() or ch == "_":
            chars = []
            while i < n and (source[i].isalnum() or source[i] == "_"):
                chars.append(source[i])
                advance()
            tokens.append(Token("IDENT", "".join(chars), start_line, start_col))
            continue

        raise PolicyError(f"unexpected character {ch!r}", source, start_line, start_col)

    tokens.append(Token("EOF", "", line, col))
    return tokens


def _describe(tok):
    if tok.kind == "EOF":
        return "end of file"
    if tok.kind == "STRING":
        return f'string "{tok.value}"'
    return repr(tok.value)


class Parser:
    """Recursive-descent parser over the token stream.

    Kept as a class (rather than free functions passing an index around)
    so error sites can always reach back to the original source text for
    rendering.
    """

    def __init__(self, source):
        self.source = source
        self.tokens = tokenize(source)
        self.pos = 0

    def _peek(self):
        return self.tokens[self.pos]

    def _advance(self):
        tok = self.tokens[self.pos]
        if tok.kind != "EOF":
            self.pos += 1
        return tok

    def _expect(self, kind, what):
        tok = self._peek()
        if tok.kind != kind:
            raise PolicyError(
                f"expected {what}, found {_describe(tok)}",
                self.source, tok.line, tok.column, max(len(tok.value), 1),
            )
        return self._advance()

    def parse_policy(self):
        kw = self._expect("IDENT", "keyword 'policy'")
        if kw.value != "policy":
            raise PolicyError(
                f"expected keyword 'policy', found {kw.value!r}",
                self.source, kw.line, kw.column, len(kw.value),
            )
        name_tok = self._expect("STRING", "a quoted policy name")
        self._expect("LBRACE", "'{' to start the policy body")

        rules = []
        seen = {}
        while self._peek().kind != "RBRACE":
            if self._peek().kind == "EOF":
                raise PolicyError(
                    "unexpected end of file inside policy body (missing '}')",
                    self.source, self._peek().line, self._peek().column,
                )
            rule = self._parse_rule()
            if rule.name in seen:
                first = seen[rule.name]
                raise PolicyError(
                    f"rule {rule.name!r} is defined twice "
                    f"(first defined on line {first.line})",
                    self.source, rule.line, rule.column, len(rule.name),
                )
            seen[rule.name] = rule
            rules.append(rule)

        self._expect("RBRACE", "'}' to close the policy body")
        self._expect("EOF", "end of input after the closing '}' (only one policy per file)")
        return Policy(name_tok.value, rules, kw.line, kw.column)

    def _parse_rule(self):
        name_tok = self._expect("IDENT", "a rule name")
        self._expect("COLON", "':' after the rule name")
        value = self._parse_value()
        validate_rule_value(self.source, name_tok.value, value)
        return Rule(name_tok.value, value, name_tok.line, name_tok.column)

    def _parse_value(self):
        tok = self._peek()
        if tok.kind == "NUMBER":
            self._advance()
            return Value("number", int(tok.value), tok.line, tok.column)
        if tok.kind == "STRING":
            self._advance()
            return Value("string", tok.value, tok.line, tok.column)
        if tok.kind == "IDENT":
            self._advance()
            return Value("ident", tok.value, tok.line, tok.column)
        if tok.kind == "LBRACKET":
            return self._parse_list()
        raise PolicyError(
            f"expected a number, identifier, string, or '[' list, found {_describe(tok)}",
            self.source, tok.line, tok.column, max(len(tok.value), 1),
        )

    def _parse_list(self):
        open_tok = self._expect("LBRACKET", "'['")
        items = []
        if self._peek().kind != "RBRACKET":
            items.append(self._parse_value())
            while self._peek().kind == "COMMA":
                self._advance()
                items.append(self._parse_value())
        self._expect("RBRACKET", "']' to close the list")
        return Value("list", items, open_tok.line, open_tok.column)


def parse(source):
    """Parse policy source text into a Policy AST, or raise PolicyError."""
    return Parser(source).parse_policy()
