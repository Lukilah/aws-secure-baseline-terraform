data "aws_caller_identity" "me" {}

# ==============================================================================
# 1. VPC & Network Hardening
# ==============================================================================
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "secure-baseline-vpc"
  }
}

# Remediation CKV_AWS_130: Disable automatic public IP assignment
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = false

  tags = {
    Name = "baseline-public-subnet"
  }
}

resource "aws_subnet" "private" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.2.0/24"

  tags = {
    Name = "baseline-private-subnet"
  }
}

# Remediation CKV2_AWS_12: Adopt and lock down the default Security Group (no ingress/egress)
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id
}

# Remediation CKV_AWS_24 & CKV2_AWS_5: Remove open SSH 0.0.0.0/0
resource "aws_security_group" "app_restricted" {
  name        = "app-restricted-sg"
  description = "Restricted ingress security group with no open public SSH"
  vpc_id      = aws_vpc.main.id

  #checkov:skip=CKV2_AWS_5: Demo baseline security group not bound to an active ENI
}

# Remediation CKV2_AWS_11: Enable VPC Flow Logging using S3 bucket target
resource "aws_flow_log" "vpc_traffic_log" {
  log_destination      = aws_s3_bucket.data.arn
  log_destination_type = "s3"
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.main.id
}

# ==============================================================================
# 2. S3 Bucket Hardening
# ==============================================================================
resource "aws_s3_bucket" "data" {
  bucket = "secure-baseline-data-${data.aws_caller_identity.me.account_id}"

  # Documented cost and scope exceptions:
  #checkov:skip=CKV_AWS_144: Cross-region replication omitted to avoid multi-region AWS billing costs for baseline demo
  #checkov:skip=CKV_AWS_18: Server access logging omitted on primary baseline bucket to prevent recursive log loop
  #checkov:skip=CKV2_AWS_62: S3 event notifications omitted as this bucket does not trigger event-driven consumers
}

# Remediation CKV2_AWS_6: Enforce S3 Public Access Block
resource "aws_s3_bucket_public_access_block" "data_pab" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Remediation CKV_AWS_21: Enable S3 Versioning for state & tamper protection
resource "aws_s3_bucket_versioning" "data_versioning" {
  bucket = aws_s3_bucket.data.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Remediation CKV_AWS_145 & CKV_AWS_19: Enable Server-Side Encryption (KMS)
resource "aws_s3_bucket_server_side_encryption_configuration" "data_encryption" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

# Remediation CKV2_AWS_61 & CKV_AWS_300: Implement lifecycle configuration & abort multipart uploads
resource "aws_s3_bucket_lifecycle_configuration" "data_lifecycle" {
  bucket = aws_s3_bucket.data.id

  rule {
    id     = "archive-and-cleanup"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = 365
    }
  }
}

# ==============================================================================
# 3. IAM Least Privilege Hardening
# ==============================================================================
# Remediation CKV_AWS_62, 63, 286, 287, 288, 289, 290, 355 & CKV2_AWS_40:
# Enforce Principle of Least Privilege with scoped actions and resource ARNs
resource "aws_iam_policy" "scoped_s3_access" {
  name        = "baseline-s3-rw-policy"
  description = "Scoped policy granting least-privilege read and write permissions to the baseline bucket"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        Resource = aws_s3_bucket.data.arn
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.data.arn}/*"
      }
    ]
  })
}
