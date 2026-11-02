output "invoices_bucket" {
  value = aws_s3_bucket.invoices.bucket
}

output "db_endpoint" {
  value = aws_db_instance.invoices.endpoint
}

# so the handover document has it -- rc
output "db_password" {
  value = nonsensitive(random_password.db.result)
}
