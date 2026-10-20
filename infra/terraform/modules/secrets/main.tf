# Secrets Manager entries for the IWS credentials, one secret per environment.
# Re-plan §8.2: KMS-encrypted, only the gateway role reads the IWS secret, every read raises an alarm.
# Values are never in code: the CTO stores them by hand (re-plan §3.2). No aws_secretsmanager_secret_version here.

resource "aws_secretsmanager_secret" "iws" {
  # checkov:skip=CKV2_AWS_57: IWS credentials are issued by Iridium and cannot be rotated by a Lambda; rotation is a manual runbook whose procedure and lead time Iridium must give in writing (re-plan §8.2).
  for_each = var.environments

  name                    = "${var.name_prefix}/iws/${each.key}"
  description             = "IWS credential for ${each.key}. Value set by the CTO only; never in code."
  kms_key_id              = var.kms_key_arn
  recovery_window_in_days = 30
  tags                    = merge(var.tags, { iws_environment = each.key })
}

# Deny reads to every principal that is not an allowed reader. With no readers listed, nobody can read the value:
# the gateway and masker roles are added when they exist (stages S2 and S3).
data "aws_iam_policy_document" "readers_only" {
  for_each = var.environments

  statement {
    sid       = "DenyReadExceptAllowedRoles"
    effect    = "Deny"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    dynamic "condition" {
      for_each = length(lookup(var.reader_role_arns, each.key, [])) > 0 ? [1] : []

      content {
        test     = "ArnNotEquals"
        variable = "aws:PrincipalArn"
        values   = var.reader_role_arns[each.key]
      }
    }
  }
}

resource "aws_secretsmanager_secret_policy" "iws" {
  for_each = var.environments

  secret_arn          = aws_secretsmanager_secret.iws[each.key].arn
  policy              = data.aws_iam_policy_document.readers_only[each.key].json
  block_public_policy = true
}

# Alarm on every read. GetSecretValue is a read-only management event, so the rule must opt in to them.
# It needs a CloudTrail trail that logs management events in this account (for example the landing zone's).
resource "aws_sns_topic" "secret_reads" {
  name              = "${replace(var.name_prefix, "/", "-")}-iws-secret-reads"
  kms_master_key_id = var.alerts_kms_key_arn
  tags              = var.tags
}

data "aws_iam_policy_document" "secret_reads_topic" {
  statement {
    sid       = "EventBridgePublishes"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.secret_reads.arn]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.secret_reads.arn]
    }
  }
}

resource "aws_sns_topic_policy" "secret_reads" {
  arn    = aws_sns_topic.secret_reads.arn
  policy = data.aws_iam_policy_document.secret_reads_topic.json
}

resource "aws_cloudwatch_event_rule" "secret_reads" {
  name        = "${replace(var.name_prefix, "/", "-")}-iws-secret-reads"
  description = "Every GetSecretValue on an IWS credential."
  state       = "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"

  event_pattern = jsonencode({
    source      = ["aws.secretsmanager"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["secretsmanager.amazonaws.com"]
      eventName   = ["GetSecretValue"]
      requestParameters = {
        secretId = [{ wildcard = "*${var.name_prefix}/iws/*" }]
      }
    }
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "secret_reads" {
  rule = aws_cloudwatch_event_rule.secret_reads.name
  arn  = aws_sns_topic.secret_reads.arn
}

resource "aws_sns_topic_subscription" "secret_reads_email" {
  for_each = var.alert_emails

  topic_arn = aws_sns_topic.secret_reads.arn
  protocol  = "email"
  endpoint  = each.value
}
