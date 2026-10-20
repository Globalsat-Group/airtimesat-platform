# TAP file archive (stage S1, only if files are at risk).
# Re-plan §4 S1 and §8.7: S3 with KMS, versioning, Object Lock in governance mode; TAP data encrypted at rest and in transit (§8.6).
# The retention period is set by Legal (re-plan §4 S0, §8.6), so it has no default.

resource "aws_s3_bucket" "this" {
  # checkov:skip=CKV_AWS_18: Server access logs need a second bucket; object-level reads and writes are audited with CloudTrail S3 data events instead (open point for the CTO: landing-zone trail or a trail in this account).
  # checkov:skip=CKV_AWS_144: Cross-region replication doubles cost and needs a second region; the region is open until ST-15 and run cost is not approved (re-plan §7, §12). Object Lock and versioning protect against deletion in the meantime.
  # checkov:skip=CKV2_AWS_62: Event notifications are not needed yet; the S1 copy job verifies sha256 and checks FSN gaps itself. Add them if the job design uses them.
  bucket              = var.bucket_name
  object_lock_enabled = true
  force_destroy       = false
  tags                = var.tags
}

resource "aws_s3_bucket_ownership_controls" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket = aws_s3_bucket.this.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.this]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    id     = "housekeeping"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    # A version becomes noncurrent only after it was overwritten or deleted. Waiting the retention period
    # from that moment means its lock has always expired first.
    noncurrent_version_expiration {
      noncurrent_days = var.retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.this]
}

data "aws_iam_policy_document" "bucket" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.this.arn,
      "${aws_s3_bucket.this.arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid       = "DenyOldTls"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.this.arn, "${aws_s3_bucket.this.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "NumericLessThan"
      variable = "s3:TlsVersion"
      values   = ["1.2"]
    }
  }

  # Objects must be written with this bucket's KMS key, never with SSE-S3 or another key.
  # Writes without encryption headers get the bucket default (this key).
  statement {
    sid       = "DenyNonKmsEncryption"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.this.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEqualsIfExists"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }

  statement {
    sid       = "DenyWrongEncryptionKey"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.this.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEqualsIfExists"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [var.kms_key_arn]
    }
  }

  # Governance mode lets any principal with s3:BypassGovernanceRetention delete locked
  # versions, and broad admin policies include it. Deny bypassing retention, and changing
  # the lock or this policy, to everyone except the listed roles (CTO decision, 20 Oct 2026).
  # aws:PrincipalArn is the role ARN (with its path) for every session of a listed role.
  # With an empty list nobody can, short of the account root user, whom S3 always lets
  # replace or delete a bucket policy (unless an SCP or RCP denies the root user).
  # Lockout: after the first apply, Terraform can change this policy (this list included),
  # the KMS key in it or the retention only when it runs as a listed role.
  statement {
    sid    = "DenyGovernanceBypass"
    effect = "Deny"
    actions = [
      "s3:BypassGovernanceRetention",        # object-level: matches bucket/*
      "s3:PutBucketObjectLockConfiguration", # IAM action of the PutObjectLockConfiguration API
      "s3:PutBucketPolicy",
      "s3:DeleteBucketPolicy",
    ]
    resources = [aws_s3_bucket.this.arn, "${aws_s3_bucket.this.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    dynamic "condition" {
      for_each = length(var.governance_admin_role_arns) > 0 ? [1] : []
      content {
        test     = "ArnNotEquals"
        variable = "aws:PrincipalArn"
        values   = var.governance_admin_role_arns
      }
    }
  }
}

resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket.this.id
  policy = data.aws_iam_policy_document.bucket.json

  # The policy denies changing the Object Lock configuration, so the default retention is set
  # before the policy exists. Otherwise the first apply can fail half-way, already locked out.
  depends_on = [
    aws_s3_bucket_public_access_block.this,
    aws_s3_bucket_object_lock_configuration.this,
  ]
}
