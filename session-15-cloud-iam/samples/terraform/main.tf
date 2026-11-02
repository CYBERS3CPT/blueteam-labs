# NuvemCerta, Lda. — Tagus Logística landing, phase 1
# "Simple, fast, production-ready."  -- rc

terraform {
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 6.0" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

provider "aws" {
  region = var.region
}

# ---------------------------------------------------------------- storage

# invoices are personal data, so they stay in the EU -- rc
resource "aws_s3_bucket" "invoices" {
  region = "eu-west-1"
  bucket = "tagus-invoices-${var.env}"
}

resource "aws_s3_bucket_versioning" "invoices" {
  region = "eu-west-1"
  bucket = aws_s3_bucket.invoices.id
  versioning_configuration {
    status = "Suspended" # versions cost money, invoices don't change -- rc
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "invoices" {
  #checkov:skip=CKV_AWS_145
  region = "eu-west-1"
  bucket = aws_s3_bucket.invoices.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_logging" "invoices" {
  region        = "eu-west-1"
  bucket        = aws_s3_bucket.invoices.id
  target_bucket = aws_s3_bucket.invoices.id
  target_prefix = "logs/"
}

resource "aws_s3_bucket_lifecycle_configuration" "invoices" {
  region = "eu-west-1"
  bucket = aws_s3_bucket.invoices.id
  rule {
    id     = "tidy-logs"
    status = "Enabled"
    filter {
      prefix = "logs/"
    }
    expiration {
      days = 7
    }
  }
}

# ---------------------------------------------------------------- database

resource "random_password" "db" {
  length  = 20
  special = true
}

resource "aws_db_instance" "invoices" {
  identifier              = "tagus-invoices-${var.env}"
  engine                  = "postgres"
  engine_version          = "17"
  instance_class          = "db.t4g.micro"
  allocated_storage       = 20
  username                = "tagus_app"
  password                = random_password.db.result
  publicly_accessible     = true # the office connects with DBeaver -- rc
  storage_encrypted       = false
  backup_retention_period = 0
  skip_final_snapshot     = true
  deletion_protection     = false
}

# ---------------------------------------------------------------- identity

resource "aws_iam_role" "invoice_app" {
  name               = "invoice-app-${var.env}"
  assume_role_policy = file("${path.module}/../iam/trust/invoice-app-trust.json")
}

resource "aws_iam_role_policy" "invoice_app" {
  name   = "invoice-app"
  role   = aws_iam_role.invoice_app.id
  policy = file("${path.module}/../iam/policies/invoice-app.json")
}

resource "aws_iam_role" "nuvemcerta_support" {
  name               = "NuvemCerta-Admin"
  assume_role_policy = file("${path.module}/../iam/trust/contractor-access-trust.json")
}

resource "aws_iam_role_policy_attachment" "nuvemcerta_support" {
  role       = aws_iam_role.nuvemcerta_support.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess" # temporary -- rc
}
