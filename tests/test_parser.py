import unittest

from pwpolicy import PolicyError, parse


class ParseStructureTests(unittest.TestCase):
    def test_parses_name_and_rules_in_order(self):
        policy = parse(
            '''
            policy "corp" {
              min_length: 12
              require: [upper, lower, digit, symbol]
            }
            '''
        )
        self.assertEqual(policy.name, "corp")
        self.assertEqual([r.name for r in policy.rules], ["min_length", "require"])

        min_length = policy.rules[0]
        self.assertEqual(min_length.value.kind, "number")
        self.assertEqual(min_length.value.data, 12)

        require = policy.rules[1]
        self.assertEqual(require.value.kind, "list")
        self.assertEqual([v.data for v in require.value.data], ["upper", "lower", "digit", "symbol"])

    def test_string_value(self):
        policy = parse('policy "corp" {\n  deny_substrings: ["hunter2"]\n}\n')
        value = policy.rules[0].value
        self.assertEqual(value.kind, "list")
        self.assertEqual(value.data[0].kind, "string")
        self.assertEqual(value.data[0].data, "hunter2")

    def test_empty_body_is_allowed(self):
        policy = parse('policy "empty" {}\n')
        self.assertEqual(policy.rules, [])

    def test_empty_list_value(self):
        policy = parse('policy "corp" {\n  deny_substrings: []\n}\n')
        self.assertEqual(policy.rules[0].value.data, [])

    def test_whitespace_between_tokens_is_not_required(self):
        policy = parse('policy "corp"{min_length:5}')
        self.assertEqual(policy.name, "corp")
        self.assertEqual(policy.rules[0].value.data, 5)

    def test_comments_are_ignored(self):
        policy = parse(
            '# leading comment\n'
            'policy "corp" { # trailing comment\n'
            '  min_length: 5 # inline\n'
            '}\n'
        )
        self.assertEqual(policy.rules[0].value.data, 5)


class ParseErrorTests(unittest.TestCase):
    def test_wrong_keyword(self):
        with self.assertRaises(PolicyError) as ctx:
            parse('polcy "corp" {}\n')
        self.assertIn("keyword 'policy'", ctx.exception.message)

    def test_missing_policy_name(self):
        with self.assertRaises(PolicyError) as ctx:
            parse('policy {}\n')
        self.assertIn("a quoted policy name", ctx.exception.message)

    def test_missing_colon_after_rule_name(self):
        with self.assertRaises(PolicyError) as ctx:
            parse('policy "corp" {\n  min_length 12\n}\n')
        err = ctx.exception
        self.assertIn("':' after the rule name", err.message)
        self.assertEqual(err.line, 2)

    def test_unclosed_brace(self):
        with self.assertRaises(PolicyError) as ctx:
            parse('policy "corp" {\n  min_length: 12\n')
        self.assertIn("missing '}'", ctx.exception.message)

    def test_duplicate_rule_name_points_at_first_definition(self):
        with self.assertRaises(PolicyError) as ctx:
            parse(
                'policy "corp" {\n'
                '  min_length: 8\n'
                '  min_length: 12\n'
                '}\n'
            )
        err = ctx.exception
        self.assertIn("defined twice", err.message)
        self.assertIn("first defined on line 2", err.message)
        self.assertEqual(err.line, 3)

    def test_only_one_policy_per_file(self):
        with self.assertRaises(PolicyError) as ctx:
            parse('policy "a" {}\npolicy "b" {}\n')
        self.assertIn("only one policy per file", ctx.exception.message)

    def test_bad_value_token(self):
        with self.assertRaises(PolicyError) as ctx:
            parse('policy "corp" {\n  min_length: :\n}\n')
        self.assertIn("expected a number, identifier, string, or '[' list", ctx.exception.message)

    def test_unclosed_list(self):
        with self.assertRaises(PolicyError) as ctx:
            parse('policy "corp" {\n  require: [upper, lower\n}\n')
        self.assertIn("']' to close the list", ctx.exception.message)


class ParseValueShapeTests(unittest.TestCase):
    def test_min_length_rejects_non_number(self):
        with self.assertRaises(PolicyError) as ctx:
            parse('policy "corp" {\n  min_length: "twelve"\n}\n')
        self.assertIn("expects a number", ctx.exception.message)

    def test_forbid_repeat_rejects_zero(self):
        with self.assertRaises(PolicyError) as ctx:
            parse('policy "corp" {\n  forbid_repeat: 0\n}\n')
        self.assertIn("must be at least 1", ctx.exception.message)

    def test_forbid_sequence_rejects_one(self):
        with self.assertRaises(PolicyError) as ctx:
            parse('policy "corp" {\n  forbid_sequence: 1\n}\n')
        self.assertIn("must be at least 2", ctx.exception.message)

    def test_require_rejects_unknown_category(self):
        with self.assertRaises(PolicyError) as ctx:
            parse('policy "corp" {\n  require: [upper, bogus]\n}\n')
        self.assertIn("unknown character category 'bogus'", ctx.exception.message)

    def test_require_rejects_non_list(self):
        with self.assertRaises(PolicyError) as ctx:
            parse('policy "corp" {\n  require: upper\n}\n')
        self.assertIn("expects a list of identifiers", ctx.exception.message)

    def test_deny_substrings_rejects_non_string_items(self):
        with self.assertRaises(PolicyError) as ctx:
            parse('policy "corp" {\n  deny_substrings: [1]\n}\n')
        self.assertIn("expects a list of strings", ctx.exception.message)

    def test_unknown_rule_name_is_not_checked_here(self):
        # validate.py has no opinion on which rule names exist; that's
        # evaluate()'s job. Parsing an unknown rule name should succeed.
        policy = parse('policy "corp" {\n  totally_made_up: 5\n}\n')
        self.assertEqual(policy.rules[0].name, "totally_made_up")


if __name__ == "__main__":
    unittest.main()
