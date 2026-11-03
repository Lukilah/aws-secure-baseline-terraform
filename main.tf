data "aws_caller_identity" "me" {}

# 1. VPC & Subnets
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
}

resource "aws_subnet" "private" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.2.0/24"
}

# 2. Insecure Security Group: Open SSH to Internet
resource "aws_security_group" "ssh_open" {
  name        = "ssh-open"
  description = "Open SSH access"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 3. Unencrypted, Unversioned S3 Bucket
resource "aws_s3_bucket" "data" {
  bucket = "secure-baseline-data-${data.aws_caller_identity.me.account_id}"
}

# 4. Overly Permissive IAM Wildcard Policy
resource "aws_iam_policy" "admin_everything" {
  name        = "admin-everything"
  description = "Excessive privilege policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}
