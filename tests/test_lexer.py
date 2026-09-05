import unittest

from pwpolicy.errors import PolicyError
from pwpolicy.parser import tokenize


class TokenizeTests(unittest.TestCase):
    def test_basic_tokens_and_positions(self):
        tokens = tokenize("foo: 1\n")
        kinds = [t.kind for t in tokens]
        self.assertEqual(kinds, ["IDENT", "COLON", "NUMBER", "EOF"])

        ident, colon, number, eof = tokens
        self.assertEqual((ident.value, ident.line, ident.column), ("foo", 1, 1))
        self.assertEqual((colon.value, colon.line, colon.column), (":", 1, 4))
        self.assertEqual((number.value, number.line, number.column), ("1", 1, 6))
        self.assertEqual((eof.line, eof.column), (2, 1))

    def test_punctuation(self):
        tokens = tokenize("{}[],:")
        kinds = [t.kind for t in tokens]
        self.assertEqual(
            kinds,
            ["LBRACE", "RBRACE", "LBRACKET", "RBRACKET", "COMMA", "COLON", "EOF"],
        )

    def test_comment_is_skipped_but_newline_still_advances_line(self):
        tokens = tokenize("foo # a comment\nbar\n")
        kinds_values = [(t.kind, t.value) for t in tokens]
        self.assertEqual(
            kinds_values,
            [("IDENT", "foo"), ("IDENT", "bar"), ("EOF", "")],
        )
        foo, bar, eof = tokens
        self.assertEqual(foo.line, 1)
        self.assertEqual(bar.line, 2)
        self.assertEqual(eof.line, 3)

    def test_string_with_escapes(self):
        # Policy source text: "a\"b" (a backslash-escaped quote, then b).
        source = '"a\\"b"'
        tokens = tokenize(source)
        self.assertEqual(tokens[0].kind, "STRING")
        self.assertEqual(tokens[0].value, 'a"b')

    def test_string_with_escaped_backslash(self):
        source = '"a\\\\b"'  # policy source text: "a\\b"
        tokens = tokenize(source)
        self.assertEqual(tokens[0].value, "a\\b")

    def test_unterminated_string_raises_located_error(self):
        with self.assertRaises(PolicyError) as ctx:
            tokenize('"abc')
        err = ctx.exception
        self.assertIn("unterminated string literal", err.message)
        self.assertEqual((err.line, err.column), (1, 1))

    def test_string_cannot_span_lines(self):
        with self.assertRaises(PolicyError) as ctx:
            tokenize('"abc\ndef"')
        self.assertIn("unterminated string literal", ctx.exception.message)

    def test_unexpected_character_raises_located_error(self):
        with self.assertRaises(PolicyError) as ctx:
            tokenize("foo: @")
        err = ctx.exception
        self.assertIn("unexpected character '@'", err.message)
        self.assertEqual((err.line, err.column), (1, 6))

    def test_number_and_ident_runs(self):
        tokens = tokenize("min_length2 123")
        ident, number, eof = tokens
        self.assertEqual((ident.kind, ident.value), ("IDENT", "min_length2"))
        self.assertEqual((number.kind, number.value), ("NUMBER", "123"))


if __name__ == "__main__":
    unittest.main()
