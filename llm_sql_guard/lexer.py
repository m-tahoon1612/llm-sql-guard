"""Very small SQL scanner.

Not a parser. It only knows enough to:
  - pull out comments,
  - blank out string literals so keywords inside them don't count,
  - split on semicolons that are outside quotes/comments.

Dollar-quoting (Postgres) and nested block comments are not handled.
"""

from dataclasses import dataclass, field


@dataclass
class Scanned:
    code: str                      # SQL with comments removed and strings replaced by ''
    comments: list[str] = field(default_factory=list)
    statements: list[str] = field(default_factory=list)


def scan(sql: str) -> Scanned:
    out: list[str] = []
    comments: list[str] = []
    i, n = 0, len(sql)

    while i < n:
        ch = sql[i]
        nxt = sql[i + 1] if i + 1 < n else ""

        if ch == "-" and nxt == "-":
            end = sql.find("\n", i)
            end = n if end == -1 else end
            comments.append(sql[i + 2:end].strip())
            out.append(" ")
            i = end
        elif ch == "#":
            # MySQL-style line comment
            end = sql.find("\n", i)
            end = n if end == -1 else end
            comments.append(sql[i + 1:end].strip())
            out.append(" ")
            i = end
        elif ch == "/" and nxt == "*":
            end = sql.find("*/", i + 2)
            end = n if end == -1 else end
            comments.append(sql[i + 2:end].strip())
            out.append(" ")
            i = end + 2
        elif ch in ("'", '"', "`"):
            quote = ch
            j = i + 1
            while j < n:
                if sql[j] == quote:
                    break
                j += 1
            if quote == "'":
                out.append("''")
            else:
                # quoted identifier, keep it (it's a name, not data)
                out.append(sql[i:j + 1])
            i = j + 1
        else:
            out.append(ch)
            i += 1

    code = "".join(out)
    statements = [s.strip() for s in code.split(";") if s.strip()]
    return Scanned(code=code, comments=comments, statements=statements)
