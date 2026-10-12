"""
SABLE Scenario Fixtures — 32 scenarios covering all required families.

Each scenario contains:
  - id, name, family, is_hard_case, notes
  - obligation: {principal, actions, protected_asset, resource_scope}
  - baseline_tf: {filename: content}
  - candidate_tf: {filename: content}

The analysis engine uses these to run the real pipeline. The engine never imports
ground_truth.py — that file is only read by the benchmark evaluator.
"""
from __future__ import annotations

# ─── Shared Terraform fragments ──────────────────────────────────────────────

_BASELINE_ROLE = '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}
'''

_BASELINE_BUCKET = '''
resource "aws_s3_bucket" "customer_data" {
  bucket = "customer-data"
  tags = {
    Asset = "customer-data"
    Stage = "production"
  }
}
'''

_BASELINE_POLICY_EXACT = '''
resource "aws_iam_role_policy" "app_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject"]
      Resource = "${aws_s3_bucket.customer_data.arn}/*"
    }]
  })
}
'''

BASELINE_INFRA = {
    "main.tf": _BASELINE_ROLE + _BASELINE_BUCKET + _BASELINE_POLICY_EXACT
}

OBLIGATION = {
    "principal": "aws_iam_role.app",
    "actions": ["s3:GetObject", "s3:PutObject"],
    "protected_asset": "aws_s3_bucket.customer_data",
    "resource_scope": "arn:aws:s3:::customer-data/*",
    "obligation_id": "S3-APPROLE-CUSTOMERDATA",
    "authority_source": "explicit benchmark policy + Terraform IAM policy document"
}


# ─── Scenarios ───────────────────────────────────────────────────────────────

SCENARIOS: dict[str, dict] = {}


def _s(id: str, name: str, family: str, notes: str, candidate_tf: dict,
       is_hard_case: bool = False, baseline_tf: dict | None = None) -> None:
    SCENARIOS[id] = {
        "id": id,
        "name": name,
        "family": family,
        "notes": notes,
        "is_hard_case": is_hard_case,
        "obligation": OBLIGATION.copy(),
        "baseline_tf": baseline_tf or BASELINE_INFRA.copy(),
        "candidate_tf": candidate_tf,
    }


# ── Family 1: Rename / Move (3 variants) ────────────────────────────────────

_s("rename_with_moved",
   "Bucket renamed with explicit moved block",
   "rename_or_move",
   "aws_s3_bucket.customer_data renamed to aws_s3_bucket.cdata with a moved{} block. Policy updated. Strongest signal set → PRESERVED.",
   {"main.tf": '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
resource "aws_s3_bucket" "cdata" {
  bucket = "customer-data"
  tags = { Asset = "customer-data" Stage = "production" }
}
resource "aws_iam_role_policy" "app_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = ["s3:GetObject", "s3:PutObject"] Resource = "${aws_s3_bucket.cdata.arn}/*" }]
  })
}
''',
    "moved.tf": '''
moved {
  from = aws_s3_bucket.customer_data
  to   = aws_s3_bucket.cdata
}
'''})


_s("rename_no_moved",
   "Bucket renamed without moved block",
   "rename_or_move",
   "No moved block, but exact physical bucket identity and stable Asset/lifecycle tags uniquely support continuity → PRESERVED.",
   {"main.tf": '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
resource "aws_s3_bucket" "customer_data_v2" {
  bucket = "customer-data"
  tags = { Asset = "customer-data" Stage = "production" }
}
resource "aws_iam_role_policy" "app_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = ["s3:GetObject", "s3:PutObject"] Resource = "${aws_s3_bucket.customer_data_v2.arn}/*" }]
  })
}
'''})


_s("move_into_module",
   "Bucket moved into a local module",
   "rename_or_move",
   "Asset moved into module.storage with module output re-exported. Application reference preserved → PRESERVED.",
   {"main.tf": '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
module "storage" {
  source = "./storage_module"
}
resource "aws_iam_role_policy" "app_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = ["s3:GetObject", "s3:PutObject"] Resource = "${module.storage.bucket_arn}/*" }]
  })
}
output "customer_data_arn" {
  value = module.storage.bucket_arn
}
''',
    "storage_module/main.tf": '''
resource "aws_s3_bucket" "customer_data" {
  bucket = "customer-data"
  tags = { Asset = "customer-data" Stage = "production" }
}
output "bucket_arn" {
  value = aws_s3_bucket.customer_data.arn
}
'''},
   is_hard_case=True)


# ── Family 2: Split (2 variants) ────────────────────────────────────────────

_s("split_to_two",
   "One bucket split into two",
   "split",
   "customer_data split into customer_data_hot and customer_data_cold. No unique successor → UNKNOWN.",
   {"main.tf": '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
resource "aws_s3_bucket" "customer_data_hot" {
  bucket = "customer-data-hot"
  tags = { Asset = "customer-data" Stage = "production" }
}
resource "aws_s3_bucket" "customer_data_cold" {
  bucket = "customer-data-cold"
  tags = { Asset = "customer-data" Stage = "production" }
}
resource "aws_iam_role_policy" "app_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = ["s3:GetObject", "s3:PutObject"] Resource = "${aws_s3_bucket.customer_data_hot.arn}/*" }]
  })
}
'''})


_s("split_tagged_successor",
   "Split with clear Asset tag marking hot as logical successor",
   "split",
   "Split but hot tier inherits the exact Asset tag from baseline; cold gets different tag. Tag evidence breaks tie.",
   {"main.tf": '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
resource "aws_s3_bucket" "customer_data_hot" {
  bucket = "customer-data-hot"
  tags = { Asset = "customer-data" Stage = "production" }
}
resource "aws_s3_bucket" "customer_data_cold" {
  bucket = "customer-data-archive"
  tags = { Asset = "customer-data-archive" Stage = "archive" }
}
resource "aws_iam_role_policy" "app_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = ["s3:GetObject", "s3:PutObject"] Resource = "${aws_s3_bucket.customer_data_hot.arn}/*" }]
  })
}
'''})


# ── Family 3: Merge (2 variants) ────────────────────────────────────────────

_s("merge_into_one",
   "Two buckets merged into one combined bucket",
   "merge",
   "customer_data and reports merged into data_combined. No unique predecessor signal → UNKNOWN.",
   {"main.tf": '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
resource "aws_s3_bucket" "data_combined" {
  bucket = "customer-data"
  tags = { Asset = "customer-data" Stage = "production" }
}
resource "aws_iam_role_policy" "app_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = ["s3:GetObject", "s3:PutObject"] Resource = "${aws_s3_bucket.data_combined.arn}/*" }]
  })
}
'''},
   baseline_tf={"main.tf": '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
resource "aws_s3_bucket" "customer_data" {
  bucket = "customer-data"
  tags = { Asset = "customer-data" Stage = "production" }
}
resource "aws_s3_bucket" "reports" {
  bucket = "reports-bucket"
  tags = { Asset = "reports" Stage = "production" }
}
resource "aws_iam_role_policy" "app_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = ["s3:GetObject", "s3:PutObject"] Resource = "${aws_s3_bucket.customer_data.arn}/*" }]
  })
}
'''})


_s("merge_preserved_identity",
   "Merge where combined bucket preserves physical identity",
   "merge",
   "Bucket name (customer-data) and Asset tag preserved → physical identity resolves successor → PRESERVED.",
   {"main.tf": '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
resource "aws_s3_bucket" "unified_store" {
  bucket = "customer-data"
  tags = { Asset = "customer-data" Stage = "production" }
}
resource "aws_iam_role_policy" "app_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = ["s3:GetObject", "s3:PutObject"] Resource = "${aws_s3_bucket.unified_store.arn}/*" }]
  })
}
'''})


# ── Family 4: Replacement with similar successor (2 variants) ────────────────

_s("replacement_preserved",
   "Bucket replaced with semantically similar successor, obligation preserved",
   "replacement",
   "Address changed, physical identity preserved (same bucket name and Asset tag) → PRESERVED.",
   {"main.tf": '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
resource "aws_s3_bucket" "app_customer_bucket" {
  bucket = "customer-data"
  tags = { Asset = "customer-data" Stage = "production" }
}
resource "aws_iam_role_policy" "app_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = ["s3:GetObject", "s3:PutObject"] Resource = "${aws_s3_bucket.app_customer_bucket.arn}/*" }]
  })
}
'''})


_s("replacement_wrong_bucket",
   "Replaced with unrelated bucket — obligation detached",
   "replacement",
   "New bucket has different physical identity and no moved, tag, or application-reference evidence; successor is unresolved → UNKNOWN.",
   {"main.tf": '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
resource "aws_s3_bucket" "new_storage" {
  bucket = "new-application-storage"
  tags = { Asset = "new-storage" Stage = "production" }
}
resource "aws_iam_role_policy" "app_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = ["s3:GetObject", "s3:PutObject"] Resource = "${aws_s3_bucket.new_storage.arn}/*" }]
  })
}
'''})


# ── Family 5: Parallel assets (2 variants) ──────────────────────────────────

_s("parallel_similar_names",
   "Two parallel S3 buckets with similar names and policies",
   "parallel_assets",
   "Two S3 buckets with nearly identical policies; no unique winner — scores too close → UNKNOWN.",
   {"main.tf": '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
resource "aws_s3_bucket" "customer_data_a" {
  bucket = "customer-data-a"
  tags = { Asset = "customer-data" Stage = "production" }
}
resource "aws_s3_bucket" "customer_data_b" {
  bucket = "customer-data-b"
  tags = { Asset = "customer-data" Stage = "production" }
}
resource "aws_iam_role_policy" "app_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = ["s3:GetObject", "s3:PutObject"] Resource = "${aws_s3_bucket.customer_data_a.arn}/*" }]
  })
}
'''})


_s("parallel_differentiated",
   "Parallel assets but only one has matching physical identity",
   "parallel_assets",
   "Two buckets but customer_data_a has identical bucket name as baseline → physical identity resolves → PRESERVED.",
   {"main.tf": '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
resource "aws_s3_bucket" "customer_data_a" {
  bucket = "customer-data"
  tags = { Asset = "customer-data" Stage = "production" }
}
resource "aws_s3_bucket" "backfill_store" {
  bucket = "backfill-storage"
  tags = { Asset = "backfill" Stage = "staging" }
}
resource "aws_iam_role_policy" "app_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = ["s3:GetObject", "s3:PutObject"] Resource = "${aws_s3_bucket.customer_data_a.arn}/*" }]
  })
}
'''})


# ── Family 6: Policy relationship rewrite (2 variants) ──────────────────────

_s("policy_rewrite_preserved",
   "Policy relationship rewritten from inline to separate resource — obligation preserved",
   "policy_relationship_rewrite",
   "Inline role policy split into separate aws_iam_role_policy resource. Same actions and resource → PRESERVED.",
   {"main.tf": '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
resource "aws_s3_bucket" "customer_data" {
  bucket = "customer-data"
  tags = { Asset = "customer-data" Stage = "production" }
}
resource "aws_iam_role_policy" "app_s3_access" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = ["s3:GetObject", "s3:PutObject"] Resource = "${aws_s3_bucket.customer_data.arn}/*" }]
  })
}
'''})


_s("policy_rewrite_wrong_target",
   "Policy relationship rewritten but now targets different bucket",
   "policy_relationship_rewrite",
   "Policy rewritten but role now targets temp_store not customer_data → misbinding → REGRESSED.",
   {"main.tf": '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
resource "aws_s3_bucket" "customer_data" {
  bucket = "customer-data"
  tags = { Asset = "customer-data" Stage = "production" }
}
resource "aws_s3_bucket" "temp_store" {
  bucket = "temp-storage"
  tags = { Asset = "temp" Stage = "production" }
}
resource "aws_iam_role_policy" "app_s3_access" {
  name   = "S3Access"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = ["s3:GetObject", "s3:PutObject"] Resource = "${aws_s3_bucket.temp_store.arn}/*" }]
  })
}
'''},
   is_hard_case=True)


# ── Family 7: Boundary valid on wrong successor (hard case) ─────────────────

_s("wrong_binding_regressed",
   "Boundary assigned to wrong logical successor",
   "wrong_binding",
   "A different bucket (logs_bucket) satisfies the local policy predicate but is the wrong logical asset → REGRESSED.",
   {"main.tf": '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
resource "aws_s3_bucket" "logs_bucket" {
  bucket = "logs-storage"
  tags = { Asset = "logs" Stage = "production" }
}
resource "aws_s3_bucket" "customer_data_new" {
  bucket = "customer-data-new"
  tags = { Asset = "customer-data-new" Stage = "production" }
}
resource "aws_iam_role_policy" "app_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = ["s3:GetObject", "s3:PutObject"] Resource = "${aws_s3_bucket.logs_bucket.arn}/*" }]
  })
}
'''},
   is_hard_case=True)


# ── Family 8: Correct successor with widened authorization ──────────────────

_s("privilege_widening",
   "Correct successor but privilege wildcard added",
   "privilege_widening",
   "Successor correctly identified via physical identity but policy now grants s3:* on * → REGRESSED (widening).",
   {"main.tf": '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
resource "aws_s3_bucket" "customer_data" {
  bucket = "customer-data"
  tags = { Asset = "customer-data" Stage = "production" }
}
resource "aws_iam_role_policy" "app_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = "s3:*" Resource = "*" }]
  })
}
'''},
   is_hard_case=True)


_s("resource_wildened",
   "Correct successor but resource scope widened to all buckets",
   "privilege_widening",
   "Actions correct but Resource changed from specific bucket to * → REGRESSED (widening).",
   {"main.tf": '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
resource "aws_s3_bucket" "customer_data" {
  bucket = "customer-data"
  tags = { Asset = "customer-data" Stage = "production" }
}
resource "aws_iam_role_policy" "app_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = ["s3:GetObject", "s3:PutObject"] Resource = "*" }]
  })
}
'''})


# ── Family 9: Correct successor with weakened authorization ─────────────────

_s("privilege_weakened_action",
   "Correct successor but PutObject action removed",
   "privilege_weakened",
   "s3:PutObject removed from the grant → REGRESSED (weakening).",
   {"main.tf": '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
resource "aws_s3_bucket" "customer_data" {
  bucket = "customer-data"
  tags = { Asset = "customer-data" Stage = "production" }
}
resource "aws_iam_role_policy" "app_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = ["s3:GetObject"] Resource = "${aws_s3_bucket.customer_data.arn}/*" }]
  })
}
'''})


_s("policy_detached",
   "Policy resource deleted — obligation completely detached",
   "privilege_weakened",
   "aws_iam_role_policy.app_policy removed entirely. No grant found → REGRESSED.",
   {"main.tf": '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
resource "aws_s3_bucket" "customer_data" {
  bucket = "customer-data"
  tags = { Asset = "customer-data" Stage = "production" }
}
'''})


# ── Family 10: Missing move metadata / conflicting evidence ─────────────────

_s("conflicting_move_and_physical",
   "moved block says A but physical identity says B",
   "conflicting_evidence",
   "moved{} points to bucket_a but bucket_b has the matching physical bucket name → conflicting evidence → UNKNOWN.",
   {"main.tf": '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
resource "aws_s3_bucket" "bucket_a" {
  bucket = "completely-different-name"
  tags = { Asset = "other" Stage = "production" }
}
resource "aws_s3_bucket" "bucket_b" {
  bucket = "customer-data"
  tags = { Asset = "customer-data" Stage = "production" }
}
resource "aws_iam_role_policy" "app_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = ["s3:GetObject", "s3:PutObject"] Resource = "${aws_s3_bucket.bucket_b.arn}/*" }]
  })
}
''',
    "moved.tf": '''
moved {
  from = aws_s3_bucket.customer_data
  to   = aws_s3_bucket.bucket_a
}
'''},
   is_hard_case=True)


_s("no_successor_found",
   "Baseline bucket completely removed — no candidate",
   "conflicting_evidence",
   "No aws_s3_bucket resources in candidate → no successor hypothesis → UNKNOWN.",
   {"main.tf": '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
resource "aws_iam_role_policy" "app_policy" {
  name   = "NoBucketPolicy"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = ["s3:GetObject"] Resource = "arn:aws:s3:::some-other-bucket/*" }]
  })
}
'''})


# ── Family 11: Ambiguous successor set (2 variants) ─────────────────────────

_s("ambiguous_set_three_candidates",
   "Three equally plausible successors",
   "ambiguous_successor",
   "Three S3 buckets with matching Asset tag and Stage, scores too close → UNKNOWN.",
   {"main.tf": '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
resource "aws_s3_bucket" "candidate_1" {
  bucket = "candidate-data-1"
  tags = { Asset = "customer-data" Stage = "production" }
}
resource "aws_s3_bucket" "candidate_2" {
  bucket = "candidate-data-2"
  tags = { Asset = "customer-data" Stage = "production" }
}
resource "aws_s3_bucket" "candidate_3" {
  bucket = "candidate-data-3"
  tags = { Asset = "customer-data" Stage = "production" }
}
resource "aws_iam_role_policy" "app_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = ["s3:GetObject", "s3:PutObject"] Resource = "${aws_s3_bucket.candidate_1.arn}/*" }]
  })
}
'''})


_s("ambiguous_resolved_by_moved",
   "Ambiguous set resolved by explicit moved block",
   "ambiguous_successor",
   "Three candidates but moved{} uniquely points to candidate_2 → PRESERVED.",
   {"main.tf": '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
resource "aws_s3_bucket" "candidate_1" {
  bucket = "candidate-data-1"
  tags = { Asset = "other-data" Stage = "staging" }
}
resource "aws_s3_bucket" "candidate_2" {
  bucket = "customer-data"
  tags = { Asset = "customer-data" Stage = "production" }
}
resource "aws_s3_bucket" "candidate_3" {
  bucket = "candidate-data-3"
  tags = { Asset = "other-data" Stage = "staging" }
}
resource "aws_iam_role_policy" "app_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = ["s3:GetObject", "s3:PutObject"] Resource = "${aws_s3_bucket.candidate_2.arn}/*" }]
  })
}
''',
    "moved.tf": '''
moved {
  from = aws_s3_bucket.customer_data
  to   = aws_s3_bucket.candidate_2
}
'''})


# ── Family 12–15: Legitimate refactors ──────────────────────────────────────

_s("locals_refactor",
   "Locals/variables refactor only — no resource changes",
   "legitimate_refactor",
   "Bucket name extracted to local variable; all resource addresses and policies unchanged → PRESERVED.",
   {"main.tf": '''
locals {
  bucket_name = "customer-data"
  asset_tag   = "customer-data"
}
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
resource "aws_s3_bucket" "customer_data" {
  bucket = local.bucket_name
  tags = { Asset = local.asset_tag Stage = "production" }
}
resource "aws_iam_role_policy" "app_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = ["s3:GetObject", "s3:PutObject"] Resource = "${aws_s3_bucket.customer_data.arn}/*" }]
  })
}
'''})


_s("policy_doc_restructure",
   "Policy document restructured but semantically identical",
   "legitimate_refactor",
   "Same actions and resource, just reformatted and renamed policy resource → PRESERVED.",
   {"main.tf": '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
resource "aws_s3_bucket" "customer_data" {
  bucket = "customer-data"
  tags   = { Asset = "customer-data" Stage = "production" }
}
resource "aws_iam_role_policy" "customer_data_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadWrite"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = "${aws_s3_bucket.customer_data.arn}/*"
      }
    ]
  })
}
'''})


_s("unrelated_resource_added",
   "Unrelated resource added — obligation unchanged",
   "legitimate_refactor",
   "A new aws_dynamodb_table added. S3 bucket and IAM policy unchanged → PRESERVED.",
   {"main.tf": '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
resource "aws_s3_bucket" "customer_data" {
  bucket = "customer-data"
  tags   = { Asset = "customer-data" Stage = "production" }
}
resource "aws_iam_role_policy" "app_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = ["s3:GetObject", "s3:PutObject"] Resource = "${aws_s3_bucket.customer_data.arn}/*" }]
  })
}
resource "aws_dynamodb_table" "sessions" {
  name         = "app-sessions"
  hash_key     = "session_id"
  billing_mode = "PAY_PER_REQUEST"
  attribute { name = "session_id" type = "S" }
}
'''})


_s("reformat_only",
   "Terraform reformatted only — no semantic change",
   "legitimate_refactor",
   "terraform fmt applied. Resources identical modulo whitespace → PRESERVED.",
   {"main.tf": '''
resource "aws_iam_role" "app" {
  name               = "app-role"
  assume_role_policy = jsonencode({ Version = "2012-10-17" Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }] })
}
resource "aws_s3_bucket" "customer_data" {
  bucket = "customer-data"
  tags   = { Asset = "customer-data" Stage = "production" }
}
resource "aws_iam_role_policy" "app_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({ Version = "2012-10-17" Statement = [{ Effect = "Allow" Action = ["s3:GetObject", "s3:PutObject"] Resource = "${aws_s3_bucket.customer_data.arn}/*" }] })
}
'''})


# ── Hard cases (6 required) ──────────────────────────────────────────────────

_s("hard_legitimate_move",
   "[Hard] Legitimate move with moved block → PRESERVED",
   "hard_case",
   "Canonical hard case: explicit moved block + physical identity + policy updated. All signals agree → PRESERVED.",
   {"main.tf": '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
resource "aws_s3_bucket" "primary_store" {
  bucket = "customer-data"
  tags = { Asset = "customer-data" Stage = "production" }
}
resource "aws_iam_role_policy" "app_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = ["s3:GetObject", "s3:PutObject"] Resource = "${aws_s3_bucket.primary_store.arn}/*" }]
  })
}
''',
    "moved.tf": '''
moved {
  from = aws_s3_bucket.customer_data
  to   = aws_s3_bucket.primary_store
}
'''},
   is_hard_case=True)


_s("hard_module_split_ambiguous",
   "[Hard] Module split — genuinely ambiguous successor → UNKNOWN",
   "hard_case",
   "Bucket moved into one of two modules with identical structure and no moved block → ambiguous → UNKNOWN.",
   {"main.tf": '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
module "storage_a" {
  source = "./storage_a"
}
module "storage_b" {
  source = "./storage_b"
}
resource "aws_iam_role_policy" "app_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = ["s3:GetObject", "s3:PutObject"] Resource = "${module.storage_a.bucket_arn}/*" }]
  })
}
''',
    "storage_a/main.tf": '''
resource "aws_s3_bucket" "customer_data" {
  bucket = "customer-data-a"
  tags = { Asset = "customer-data" Stage = "production" }
}
output "bucket_arn" { value = aws_s3_bucket.customer_data.arn }
''',
    "storage_b/main.tf": '''
resource "aws_s3_bucket" "customer_data" {
  bucket = "customer-data-b"
  tags = { Asset = "customer-data" Stage = "production" }
}
output "bucket_arn" { value = aws_s3_bucket.customer_data.arn }
'''},
   is_hard_case=True)


_s("hard_wrong_binding",
   "[Hard] Wrong binding — REGRESSED even if different resource satisfies local policy",
   "hard_case",
   "logs_bucket satisfies the local predicate but is not the logical successor of customer_data → REGRESSED.",
   # Reuses scenario wrong_binding_regressed above but tagged hard_case
   {"main.tf": '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
resource "aws_s3_bucket" "logs_bucket" {
  bucket = "logs-archive"
  tags = { Asset = "logs" Stage = "production" }
}
resource "aws_s3_bucket" "customer_new" {
  bucket = "customer-data-new"
  tags = { Asset = "other" Stage = "production" }
}
resource "aws_iam_role_policy" "app_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = ["s3:GetObject", "s3:PutObject"] Resource = "${aws_s3_bucket.logs_bucket.arn}/*" }]
  })
}
'''},
   is_hard_case=True)


_s("hard_privilege_widening",
   "[Hard] Privilege widening → REGRESSED",
   "hard_case",
   "Correct successor confirmed by moved block + physical identity. But s3:* wildcard added → REGRESSED (widening).",
   {"main.tf": '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
resource "aws_s3_bucket" "main_store" {
  bucket = "customer-data"
  tags = { Asset = "customer-data" Stage = "production" }
}
resource "aws_iam_role_policy" "app_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"] Resource = ["${aws_s3_bucket.main_store.arn}/*", "${aws_s3_bucket.main_store.arn}"] }]
  })
}
''',
    "moved.tf": '''
moved {
  from = aws_s3_bucket.customer_data
  to   = aws_s3_bucket.main_store
}
'''},
   is_hard_case=True)


_s("hard_conflicting_evidence",
   "[Hard] Conflicting evidence → UNKNOWN",
   "hard_case",
   "moved block and physical identity point to different candidates. Evidence conflicts → UNKNOWN.",
   {"main.tf": '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
resource "aws_s3_bucket" "store_x" {
  bucket = "unrelated-store"
  tags = { Asset = "unrelated" Stage = "dev" }
}
resource "aws_s3_bucket" "store_y" {
  bucket = "customer-data"
  tags = { Asset = "customer-data" Stage = "production" }
}
resource "aws_iam_role_policy" "app_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = ["s3:GetObject", "s3:PutObject"] Resource = "${aws_s3_bucket.store_y.arn}/*" }]
  })
}
''',
    "moved.tf": '''
moved {
  from = aws_s3_bucket.customer_data
  to   = aws_s3_bucket.store_x
}
'''},
   is_hard_case=True)


# ── Additional variants to reach 32 ────────────────────────────────────────

_s("exact_unchanged",
   "No changes at all — identical baseline and candidate",
   "legitimate_refactor",
   "Terraform files copied as-is. Same addresses, same policies → PRESERVED.",
   BASELINE_INFRA.copy())


_s("extra_get_action_wildcard",
   "s3:GetObject* wildcard added to grant",
   "privilege_widening",
   "s3:GetObject* covers GetObject but also GetObjectAcl, GetObjectTagging etc. → REGRESSED (widening).",
   {"main.tf": '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
resource "aws_s3_bucket" "customer_data" {
  bucket = "customer-data"
  tags   = { Asset = "customer-data" Stage = "production" }
}
resource "aws_iam_role_policy" "app_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = ["s3:Get*", "s3:PutObject"] Resource = "${aws_s3_bucket.customer_data.arn}/*" }]
  })
}
'''})


def get_scenarios_list() -> list[dict]:
    """Return scenario metadata without TF content for the UI scenario picker."""
    return [
        {
            "id": s["id"],
            "name": s["name"],
            "family": s["family"],
            "is_hard_case": s["is_hard_case"],
            "notes": s["notes"],
        }
        for s in SCENARIOS.values()
    ]
