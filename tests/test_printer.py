import unittest

from pwpolicy import format_policies, format_policy, parse, parse_all
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


class FormatPoliciesTests(unittest.TestCase):
    def test_separates_policies_with_a_blank_line(self):
        policies = parse_all(
            'policy "default" {\n  min_length: 8\n}\n'
            'policy "strict" {\n  min_length: 16\n}\n'
        )
        self.assertEqual(
            format_policies(policies),
            'policy "default" {\n  min_length: 8\n}\n'
            "\n"
            'policy "strict" {\n  min_length: 16\n}\n',
        )

    def test_round_trips_through_parse_all(self):
        source = (
            'policy "default" {\n  min_length: 8\n}\n'
            "\n"
            'policy "strict" {\n  min_length: 16\n}\n'
        )
        once = format_policies(parse_all(source))
        twice = format_policies(parse_all(once))
        self.assertEqual(once, twice)
        self.assertEqual(once, source)


if __name__ == "__main__":
    unittest.main()
