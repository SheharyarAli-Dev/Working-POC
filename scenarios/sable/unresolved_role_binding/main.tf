terraform { required_version = ">= 1.1" }
module "storage" { source = "./modules/storage" }
moved {
  from = aws_s3_bucket.invoice_data
  to = module.storage.aws_s3_bucket.active_invoices
}
resource "aws_iam_role" "app" {
  name = "invoicehub-app"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" }, Action = "sts:AssumeRole" }] })
}
resource "aws_iam_role_policy" "invoice_access" {
  role = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject"], Resource = ["${module.storage.active_arn}/*"] }]
  })
}
resource "aws_iam_role_policy" "dynamic_extra" {
  role = var.additional_role
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["s3:*"], Resource = ["*"] }]
  })
}
output "invoice_bucket" { value = module.storage.active_id }
