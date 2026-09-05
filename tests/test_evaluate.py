import unittest

from pwpolicy import evaluate, parse
from pwpolicy.parser import Policy, Rule, Value


def _rule_names(result):
    return [v.rule for v in result.violations]


class EvaluateSingleRuleTests(unittest.TestCase):
    def test_min_length(self):
        policy = parse('policy "p" {\n  min_length: 5\n}\n')
        self.assertFalse(evaluate(policy, "abcd").ok)
        self.assertTrue(evaluate(policy, "abcde").ok)

    def test_max_length(self):
        policy = parse('policy "p" {\n  max_length: 5\n}\n')
        self.assertTrue(evaluate(policy, "abcde").ok)
        self.assertFalse(evaluate(policy, "abcdef").ok)

    def test_require_reports_each_missing_category(self):
        policy = parse('policy "p" {\n  require: [upper, digit]\n}\n')
        result = evaluate(policy, "abc")
        self.assertFalse(result.ok)
        self.assertIn("upper", result.violations[0].message)
        self.assertIn("digit", result.violations[0].message)
        self.assertTrue(evaluate(policy, "Abc1").ok)

    def test_min_unique(self):
        policy = parse('policy "p" {\n  min_unique: 3\n}\n')
        self.assertFalse(evaluate(policy, "aab").ok)
        self.assertTrue(evaluate(policy, "abc").ok)

    def test_forbid_repeat(self):
        policy = parse('policy "p" {\n  forbid_repeat: 3\n}\n')
        self.assertTrue(evaluate(policy, "aab").ok)
        result = evaluate(policy, "xaaab")
        self.assertFalse(result.ok)
        self.assertIn("'a' x3", result.violations[0].message)

    def test_forbid_sequence_ascending_and_descending(self):
        policy = parse('policy "p" {\n  forbid_sequence: 3\n}\n')
        self.assertTrue(evaluate(policy, "xaczy").ok)
        self.assertFalse(evaluate(policy, "xabcy").ok)
        self.assertFalse(evaluate(policy, "x321y").ok)

    def test_deny_substrings_is_case_insensitive(self):
        policy = parse('policy "p" {\n  deny_substrings: ["password", "qwerty"]\n}\n')
        self.assertTrue(evaluate(policy, "Secure99").ok)
        result = evaluate(policy, "myPassWord1")
        self.assertFalse(result.ok)
        self.assertIn("password", result.violations[0].message)


class EvaluateWholePolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = parse(
            'policy "corp" {\n'
            "  min_length: 8\n"
            "  require: [upper, lower, digit]\n"
            '  deny_substrings: ["password"]\n'
            "}\n"
        )

    def test_passing_password(self):
        result = evaluate(self.policy, "Sunrise7")
        self.assertTrue(result.ok)
        self.assertEqual(result.violations, [])

    def test_failing_password_reports_every_broken_rule(self):
        result = evaluate(self.policy, "password")
        self.assertFalse(result.ok)
        self.assertEqual(
            set(_rule_names(result)),
            {"require", "deny_substrings"},
        )


class EvaluateErrorHandlingTests(unittest.TestCase):
    def test_unknown_rule_name_raises(self):
        policy = Policy(
            "p",
            [Rule("bogus", Value("number", 1, 1, 1), 1, 1)],
            1, 1,
        )
        with self.assertRaises(ValueError) as ctx:
            evaluate(policy, "whatever")
        self.assertIn("unknown rule 'bogus'", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
