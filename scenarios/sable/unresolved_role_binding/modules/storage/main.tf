resource "aws_s3_bucket" "active_invoices" {
  bucket = "invoicehub-data-local-demo"
  tags = { Asset = "invoice-ledger", Stage = "active" }
}
resource "aws_s3_bucket" "archive_invoices" {
  bucket = "invoicehub-archive-local-demo"
  tags = { Asset = "invoice-ledger", Stage = "archive" }
}
output "active_arn" { value = aws_s3_bucket.active_invoices.arn }
output "archive_arn" { value = aws_s3_bucket.archive_invoices.arn }
output "active_id" { value = aws_s3_bucket.active_invoices.id }
