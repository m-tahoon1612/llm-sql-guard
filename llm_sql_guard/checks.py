import re
from dataclasses import dataclass, field

from .lexer import scan

DEFAULT_ALLOWED = frozenset({"SELECT", "WITH"})

WRITE_KEYWORDS = ("DROP", "DELETE", "UPDATE", "TRUNCATE", "INSERT", "MERGE",
                  "ALTER", "CREATE", "GRANT", "REVOKE", "REPLACE")

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

    ok = not any(f.severity == "error" for f in findings)
    return Result(ok=ok, findings=findings)
