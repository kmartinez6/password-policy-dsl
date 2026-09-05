import unittest

from pwpolicy import format_policy, parse
from pwpolicy.parser import Policy, Rule, Value


class FormatPolicyTests(unittest.TestCase):
    def test_canonical_spacing_regardless_of_input_layout(self):
        policy = parse('policy "corp"{min_length:5}')
        self.assertEqual(
            format_policy(policy),
            'policy "corp" {\n  min_length: 5\n}\n',
        )

    def test_list_layout(self):
        policy = parse('policy "corp" {\n  require: [upper,lower,   digit]\n}\n')
        self.assertEqual(
            format_policy(policy),
            'policy "corp" {\n  require: [upper, lower, digit]\n}\n',
        )

    def test_empty_list(self):
        policy = parse('policy "corp" {\n  deny_substrings: []\n}\n')
        self.assertEqual(
            format_policy(policy),
            'policy "corp" {\n  deny_substrings: []\n}\n',
        )

    def test_empty_body(self):
        policy = parse('policy "corp" {}\n')
        self.assertEqual(format_policy(policy), 'policy "corp" {\n}\n')

    def test_round_trips_through_parse(self):
        source = (
            'policy "corporate-default" {\n'
            "  min_length: 12\n"
            "  max_length: 128\n"
            "  require: [upper, lower, digit, symbol]\n"
            "  min_unique: 6\n"
            "  forbid_repeat: 3\n"
            "  forbid_sequence: 3\n"
            '  deny_substrings: ["password", "qwerty", "letmein"]\n'
            "}\n"
        )
        once = format_policy(parse(source))
        twice = format_policy(parse(once))
        self.assertEqual(once, twice)
        self.assertEqual(once, source)

    def test_escapes_quotes_and_backslashes_round_trip(self):
        # Built by hand rather than typed as policy source, so the test
        # doesn't depend on getting escaping right twice.
        tricky = 'quote " and backslash \\ together'
        value = Value("string", tricky, 1, 1)
        rule = Rule("deny_substrings", Value("list", [value], 1, 1), 1, 1)
        policy = Policy("t", [rule], 1, 1)

        text = format_policy(policy)
        reparsed = parse(text)

        self.assertEqual(reparsed.rules[0].value.data[0].data, tricky)


if __name__ == "__main__":
    unittest.main()
