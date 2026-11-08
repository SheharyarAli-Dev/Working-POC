#!/bin/sh
# Make a small sample git repository for checking an installed `asent` (CI: .github/workflows/package.yml).
#   make_sample_repo.sh DEST ASENT_SOURCE accept|block
# Branch main, base commit: the InvoiceHub Terraform (infra/), a reviewed .asent/ that enables only SABLE,
# and one SABLE obligation. Head commit (checked out):
#   accept: a docs-only change          -> asent gate decides ACCEPT (exit 0)
#   block:  scenarios/sable/regressed   -> asent gate decides BLOCK  (exit 1)
# The same cases as tests/test_gate_cli.py (test_sable_preserved_is_accept, test_sable_regression_is_block).
set -eu
dest=$1 src=$2 mode=$3
case "$mode" in accept|block) ;; *) echo "mode must be accept or block" >&2; exit 2 ;; esac
[ ! -e "$dest" ] || { echo "$dest already exists" >&2; exit 2; }
mkdir -p "$dest/infra" "$dest/.asent/sable"
cp "$src"/demo_project/InvoiceHub/infra/*.tf "$dest/infra/"
cat > "$dest/.asent/config.json" <<'JSON'
{"schema_version": 1, "project": {"name": "asent-sample"},
 "modules": {"SABLE": {"enabled": true},
             "CAVR": {"enabled": false, "reason": "sample has no Python dependencies"},
             "SATRA": {"enabled": false, "reason": "sample has no application code"}}}
JSON
cat > "$dest/.asent/sable/obligations.json" <<'JSON'
{"obligations": [{"id": "invoice-data", "principal": "aws_iam_role.app", "protected_asset": "aws_s3_bucket.invoice_data",
                  "actions": ["s3:GetObject", "s3:PutObject"]}]}
JSON
g() { git -C "$dest" -c user.email=ci@example.invalid -c user.name="ASENT CI" -c core.hooksPath=/dev/null "$@"; }
g init -q -b main
g add -A && g commit -q -m "base: infra and reviewed .asent"
g checkout -q -b change
if [ "$mode" = accept ]; then
  echo "docs only" > "$dest/README.md"
else
  rm -f "$dest"/infra/*.tf
  cp -R "$src"/scenarios/sable/regressed/. "$dest/infra/"
fi
g add -A && g commit -q -m "head: $mode"
echo "$dest: main <- change ($mode)"
