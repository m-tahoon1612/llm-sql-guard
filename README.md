# llm-sql-guard

Small checker for SQL that you didn't write yourself - mostly text-to-SQL output
from an LLM, but it works for anything you want to sanity check before it hits
a database.

I kept running into the same issues when wiring models up to a warehouse:
`SELECT *` on a fact table, a stray `; DROP ...`, or instructions tucked into a
comment. This is a set of cheap, boring checks that run before the query does.

It is **not** a SQL parser and not a security boundary. Use a read-only
database role as well. This just catches the obvious stuff early and gives the
model a clear error to retry on.

## What it checks

| rule              | severity | what                                                  |
|-------------------|----------|-------------------------------------------------------|
| statement-type    | error    | first keyword not in allowlist (default SELECT, WITH)  |
| write-keyword     | error    | DROP/DELETE/UPDATE/... anywhere in the statement       |
| multi-statement   | error    | more than one statement                                |
| comment-payload   | error    | comments containing write keywords or "ignore ..."     |
| union-nulls       | error    | `UNION SELECT NULL, NULL, ...` column probing          |
| union-catalog     | error    | UNION reading information_schema / pg_catalog etc.     |
| tautology         | error    | `OR 1=1`, `OR ''=''`, `OR true`                        |
| no-where-write    | error    | DELETE/UPDATE without WHERE                            |
| select-star       | warn     | `SELECT *` or `t.*`                                    |
| unbounded-scan    | warn     | no WHERE/LIMIT on tables named like events/logs/fact_  |

## Usage

No dependencies. Python 3.11+.

```
python -m llm_sql_guard check "SELECT * FROM events"
python -m llm_sql_guard check --file examples/unsafe/stacked_drop.sql
echo "SELECT 1" | python -m llm_sql_guard check
python -m llm_sql_guard check --json --strict --file query.sql
python -m llm_sql_guard check --allow SELECT,INSERT "INSERT INTO t VALUES (1)"
```

Exit code is 1 when there's an error (or any finding with `--strict`).

```
$ python -m llm_sql_guard check --file examples/unsafe/stacked_drop.sql
ERROR  multi-statement  2 statements; only one is allowed
ERROR  statement-type   stmt 2: DROP is not in allowlist ['SELECT', 'WITH']
FAIL
```

As a library:

```python
from llm_sql_guard import check_sql

res = check_sql(model_output)
if not res.ok:
    retry_with_feedback([f.message for f in res.findings])
```

## Tests

```
python -m unittest discover -s tests -t .
```

## Limitations

- Regex + a tiny lexer. Postgres dollar-quoting and nested comments aren't handled.
- "Large table" detection is just table naming. Edit `LARGE_TABLE_HINTS`.
- Dialect differences (backticks vs double quotes etc.) are handled loosely.
- TODO: optional sqlglot backend for a real AST when it's installed.

MIT licensed.
