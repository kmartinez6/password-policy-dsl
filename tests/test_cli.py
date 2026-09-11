import io
import os
import tempfile
import unittest

from pwpolicy.cli import main

_POLICY_SOURCE = (
    'policy "corp" {\n'
    "  min_length: 8\n"
    "  require: [upper, lower, digit]\n"
    '  deny_substrings: ["password"]\n'
    "}\n"
)


class CliTests(unittest.TestCase):
    def setUp(self):
        fd, self.policy_path = tempfile.mkstemp(suffix=".policy")
        with os.fdopen(fd, "w") as f:
            f.write(_POLICY_SOURCE)
        self.addCleanup(os.remove, self.policy_path)

    def _run(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        code = main(list(argv), out=out, err=err)
        return code, out.getvalue(), err.getvalue()

    def test_passing_password_exits_zero(self):
        code, out, err = self._run("check", self.policy_path, "Sunrise7!")
        self.assertEqual(code, 0)
        self.assertIn("OK", out)
        self.assertIn("corp", out)
        self.assertEqual(err, "")

    def test_failing_password_exits_one_and_lists_violations(self):
        code, out, err = self._run("check", self.policy_path, "password")
        self.assertEqual(code, 1)
        self.assertIn("FAIL", out)
        self.assertIn("require", out)
        self.assertIn("deny_substrings", out)
        self.assertEqual(err, "")

    def test_missing_policy_file_exits_two(self):
        code, out, err = self._run("check", "/no/such/policy.txt", "whatever")
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("can't read", err)

    def test_malformed_policy_exits_two_with_location(self):
        fd, path = tempfile.mkstemp(suffix=".policy")
        with os.fdopen(fd, "w") as f:
            f.write('policy "corp" {\n  min_length 12\n}\n')
        self.addCleanup(os.remove, path)

        code, out, err = self._run("check", path, "whatever")
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("line 2, column", err)

    def test_unknown_rule_exits_two(self):
        fd, path = tempfile.mkstemp(suffix=".policy")
        with os.fdopen(fd, "w") as f:
            f.write('policy "corp" {\n  made_up_rule: 1\n}\n')
        self.addCleanup(os.remove, path)

        code, out, err = self._run("check", path, "whatever")
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("unknown rule", err)


if __name__ == "__main__":
    unittest.main()
