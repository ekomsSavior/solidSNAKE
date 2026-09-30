#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${1:-${RANGER_C3_DIR:-/tmp/RANGER_C3}/internal/api/dashboard.go}"

if [ ! -f "$SRC" ]; then
    echo "extract_dashboard: missing reference file: $SRC" >&2
    exit 1
fi

python3 - "$SRC" "$ROOT/src/dashboard_html.cpp" <<'PYEOF'
import sys

src, out = sys.argv[1], sys.argv[2]
text = open(src, encoding="utf-8").read()
start = text.index("`") + 1
end = text.rindex("`")
asset = text[start:end]
assert ")SNAKEDASH\"" not in asset, "asset collides with the raw-string delimiter"
assert "`" not in asset, "Go raw strings cannot contain a backtick"
body = (
    "#include <string>\n\n"
    "namespace snake::api {\n\n"
    "const char* kDashboardHTML = R\"SNAKEDASH(" + asset + ")SNAKEDASH\";\n\n"
    "const std::string& embedded_dashboard_html() {\n"
    "    static const std::string html(kDashboardHTML);\n"
    "    return html;\n"
    "}\n\n"
    "}  // namespace snake::api\n"
)
open(out, "w", encoding="utf-8").write(body)
print("extract_dashboard: wrote %s (%d bytes asset)" % (out, len(asset)))
PYEOF
