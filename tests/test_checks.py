import pathlib
import unittest

from llm_sql_guard import check_sql
from llm_sql_guard.lexer import scan

EXAMPLES = pathlib.Path(__file__).resolve().parent.parent / "examples"


def rules(sql, **kw):
    return {f.rule for f in check_sql(sql, **kw).findings}


class LexerTests(unittest.TestCase):
    def test_semicolon_in_string_is_not_split(self):
        s = scan("SELECT 'a;b' FROM t")
        self.assertEqual(len(s.statements), 1)

    def test_comments_are_collected(self):
        s = scan("SELECT 1 -- hi\n/* there */")
        self.assertEqual(s.comments, ["hi", "there"])



class CheckTests(unittest.TestCase):
    def test_plain_select_ok(self):
        self.assertTrue(check_sql("SELECT id FROM users WHERE id = 1").ok)

    def test_keyword_inside_string_ignored(self):
        self.assertTrue(check_sql("SELECT id FROM t WHERE note = 'drop table x'").ok)

    def test_select_star_warns(self):
        r = check_sql("SELECT * FROM users WHERE id = 1")
        self.assertTrue(r.ok)
        self.assertIn("select-star", {f.rule for f in r.findings})

    def test_unbounded_scan_on_events(self):
        self.assertIn("unbounded-scan", rules("SELECT user_id FROM events"))
        self.assertNotIn("unbounded-scan", rules("SELECT user_id FROM events LIMIT 10"))

    def test_drop_blocked(self):
        self.assertFalse(check_sql("DROP TABLE users").ok)

    def test_allowlist_can_be_widened(self):
        r = check_sql("UPDATE users SET a = 1 WHERE id = 3", allowed={"SELECT", "UPDATE"})
        self.assertTrue(r.ok)

    def test_update_without_where(self):
        r = check_sql("UPDATE users SET a = 1", allowed={"UPDATE"})
        self.assertIn("no-where-write", {f.rule for f in r.findings})

    def test_cte_hiding_delete(self):
        self.assertIn("write-keyword",
                      rules("WITH x AS (DELETE FROM t RETURNING *) SELECT id FROM x"))



class FixtureTests(unittest.TestCase):
    def test_safe_examples_pass(self):
        for f in sorted((EXAMPLES / "safe").glob("*.sql")):
            with self.subTest(f.name):
                self.assertTrue(check_sql(f.read_text()).ok, f.name)

    def test_unsafe_examples_fail_in_strict(self):
        for f in sorted((EXAMPLES / "unsafe").glob("*.sql")):
            with self.subTest(f.name):
                r = check_sql(f.read_text())
                self.assertTrue(not r.ok or r.findings, f.name)


if __name__ == "__main__":
    unittest.main()
