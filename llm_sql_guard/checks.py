import re
from dataclasses import dataclass, field

from .lexer import scan

DEFAULT_ALLOWED = frozenset({"SELECT", "WITH"})

WRITE_KEYWORDS = ("DROP", "DELETE", "UPDATE", "TRUNCATE", "INSERT", "MERGE",
                  "ALTER", "CREATE", "GRANT", "REVOKE", "REPLACE")

# Table names that usually mean "this is big, don't scan it unfiltered".
# Purely a naming heuristic - tune it for your warehouse.
LARGE_TABLE_HINTS = re.compile(
    r"(events?|logs?|clicks?|pageviews?|impressions?|fact_|_fact|raw_|sessions?|transactions?)",
    re.IGNORECASE,
)

SUSPICIOUS_COMMENT = re.compile(
    r"\b(drop|delete|update|truncate|insert|exec|grant|ignore|instruction|system)\b",
    re.IGNORECASE,
)

# OR 1=1, OR 'a'='a' (strings are blanked by the lexer, so that becomes ''=''), OR true
TAUTOLOGY = re.compile(r"(?:\bOR\s+(\d+)\s*=\s*\1\b|''\s*=\s*''|\bTRUE\b)", re.IGNORECASE)


@dataclass
class Finding:
    rule: str
    severity: str  # "error" or "warn"
    message: str


@dataclass
class Result:
    ok: bool
    findings: list[Finding] = field(default_factory=list)


def _first_keyword(stmt: str) -> str:
    m = re.match(r"\s*\(*\s*([A-Za-z]+)", stmt)
    return m.group(1).upper() if m else ""


def _tables(stmt: str) -> list[str]:
    return re.findall(r"\b(?:FROM|JOIN)\s+([A-Za-z_][\w.\"`]*)", stmt, re.IGNORECASE)


def check_sql(sql: str, allowed: frozenset[str] | set[str] = DEFAULT_ALLOWED,
              allow_multi: bool = False) -> Result:
    findings: list[Finding] = []
    scanned = scan(sql)
    allowed = {a.upper() for a in allowed}

    if not scanned.statements:
        return Result(ok=False, findings=[Finding("empty", "error", "no SQL statement found")])

    if len(scanned.statements) > 1 and not allow_multi:
        findings.append(Finding("multi-statement", "error",
                                f"{len(scanned.statements)} statements; only one is allowed"))

    for c in scanned.comments:
        if SUSPICIOUS_COMMENT.search(c):
            findings.append(Finding("comment-payload", "error",
                                    f"comment contains suspicious text: {c[:60]!r}"))

    for idx, stmt in enumerate(scanned.statements, 1):
        prefix = f"stmt {idx}: " if len(scanned.statements) > 1 else ""
        kw = _first_keyword(stmt)
        upper = stmt.upper()

        if kw not in allowed:
            findings.append(Finding("statement-type", "error",
                                    f"{prefix}{kw or '?'} is not in allowlist {sorted(allowed)}"))

        # write keywords hiding later in the statement, e.g. WITH x AS (DELETE ... RETURNING)
        for w in WRITE_KEYWORDS:
            if w != kw and re.search(rf"\b{w}\b", upper) and w.upper() not in allowed:
                findings.append(Finding("write-keyword", "error",
                                        f"{prefix}found {w} inside statement"))

        if re.search(r"SELECT\s+(DISTINCT\s+)?\*", upper) or re.search(r"\w+\.\*", stmt):
            findings.append(Finding("select-star", "warn",
                                    f"{prefix}SELECT * - list the columns you need"))

        if kw in ("SELECT", "WITH"):
            big = [t for t in _tables(stmt) if LARGE_TABLE_HINTS.search(t)]
            has_filter = re.search(r"\bWHERE\b", upper)
            has_limit = re.search(r"\bLIMIT\s+\d+", upper)
            if big and not has_filter and not has_limit:
                findings.append(Finding("unbounded-scan", "warn",
                                        f"{prefix}no WHERE/LIMIT on {', '.join(big)}"))

        if kw in ("DELETE", "UPDATE") and "WHERE" not in upper:
            findings.append(Finding("no-where-write", "error",
                                    f"{prefix}{kw} without WHERE touches every row"))

        unions = len(re.findall(r"\bUNION\b", upper))
        if unions:
            if re.search(r"\bUNION\s+(ALL\s+)?SELECT\s+(NULL\s*,\s*){2,}", upper):
                findings.append(Finding("union-nulls", "error",
                                        f"{prefix}UNION SELECT NULL,NULL,... looks like column probing"))
            if re.search(r"\b(information_schema|pg_catalog|sqlite_master|mysql\.user)\b", stmt, re.I):
                findings.append(Finding("union-catalog", "error",
                                        f"{prefix}UNION reads from system catalog"))
            if unions > 3:
                findings.append(Finding("union-many", "warn", f"{prefix}{unions} UNIONs"))

        if TAUTOLOGY.search(stmt):
            findings.append(Finding("tautology", "error",
                                    f"{prefix}OR with always-true condition (1=1 style)"))

    ok = not any(f.severity == "error" for f in findings)
    return Result(ok=ok, findings=findings)
