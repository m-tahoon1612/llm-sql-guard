import argparse
import sys

from .checks import DEFAULT_ALLOWED, check_sql


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="llm_sql_guard",
                                description="Check SQL before you run it.")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="check a query")
    c.add_argument("sql", nargs="?", help="SQL string (or use --file / stdin)")
    c.add_argument("--file", "-f", help="read SQL from file")
    c.add_argument("--allow", default=",".join(sorted(DEFAULT_ALLOWED)),
                   help="comma separated statement types (default: SELECT,WITH)")
    c.add_argument("--allow-multi", action="store_true", help="permit several statements")
    args = p.parse_args(argv)

    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            sql = fh.read()
    elif args.sql:
        sql = args.sql
    elif not sys.stdin.isatty():
        sql = sys.stdin.read()
    else:
        p.error("pass SQL as an argument, --file, or via stdin")

    allowed = {a.strip().upper() for a in args.allow.split(",") if a.strip()}
    res = check_sql(sql, allowed=allowed, allow_multi=args.allow_multi)
    failed = not res.ok

    for f in res.findings:
        print(f"{f.severity.upper():5}  {f.rule:16} {f.message}")
    print("FAIL" if failed else "OK")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
