"""Error type shared by the lexer and parser.

The point of this module is that every failure carries a line, a column,
and enough of the source to show the reader exactly where it went wrong,
rather than a bare "syntax error" with no location.
"""


class PolicyError(Exception):
    def __init__(self, message, source, line, column, length=1):
        self.message = message
        self.line = line
        self.column = column
        self.length = max(length, 1)
        super().__init__(self._render(source))

    def _render(self, source):
        lines = source.splitlines() or [""]
        idx = self.line - 1
        context = lines[idx] if 0 <= idx < len(lines) else ""
        pointer = " " * (self.column - 1) + "^" * self.length
        return (
            f"line {self.line}, column {self.column}: {self.message}\n"
            f"    {context}\n"
            f"    {pointer}"
        )
