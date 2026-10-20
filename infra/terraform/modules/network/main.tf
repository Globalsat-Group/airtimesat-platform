# Gateway network: egress only, no inbound from the internet.
# One NAT gateway with a fixed Elastic IP, because ST-15 needs a static egress IP and Iridium is later asked
# to enforce an IP allowlist tied to it (re-plan §8.2; Annex F §7.2).
# Workloads run only in the private subnets; the public subnet holds the NAT gateway and nothing else.

data "aws_region" "current" {}

# Pin the zones by name (a, b, c exist in every ST-15 candidate region) so the set never changes on its own.
data "aws_availability_zones" "pinned" {
  state = "available"

  filter {
    name   = "zone-name"
    values = formatlist("%s%s", data.aws_region.current.region, ["a", "b", "c"])
  }
}

locals {
  azs = slice(sort(data.aws_availability_zones.pinned.names), 0, var.private_subnet_count)
}

resource "aws_vpc" "this" {
  cidr_block           = var.cidr_block
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(var.tags, { Name = var.name })
}

# Lock down the default security group so nothing can use it by accident.
resource "aws_default_security_group" "this" {
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = "${var.name}-default-unused" })
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = var.name })
}

resource "aws_subnet" "public_nat" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = cidrsubnet(var.cidr_block, 4, 0)
  availability_zone       = local.azs[0]
  map_public_ip_on_launch = false
  tags                    = merge(var.tags, { Name = "${var.name}-public-nat" })
}

resource "aws_subnet" "private" {
  count = var.private_subnet_count

  vpc_id                  = aws_vpc.this.id
  cidr_block              = cidrsubnet(var.cidr_block, 4, count.index + 1)
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = false
  tags                    = merge(var.tags, { Name = "${var.name}-private-${local.azs[count.index]}" })
}

resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = merge(var.tags, { Name = "${var.name}-nat-egress" })
}

resource "aws_nat_gateway" "this" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public_nat.id
  tags          = merge(var.tags, { Name = var.name })

  depends_on = [aws_internet_gateway.this]
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = "${var.name}-public" })
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "public_nat" {
  subnet_id      = aws_subnet.public_nat.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = "${var.name}-private" })
}

resource "aws_route" "private_egress" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this.id
}

resource "aws_route_table_association" "private" {
  count = var.private_subnet_count

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# Network ACLs. Private subnets accept only return traffic for connections they opened.
resource "aws_network_acl" "private" {
  vpc_id     = aws_vpc.this.id
  subnet_ids = aws_subnet.private[*].id
  tags       = merge(var.tags, { Name = "${var.name}-private" })

  egress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }

  # Traffic inside the VPC (later: the database the gateway uses for its lease).
  egress {
    rule_no    = 110
    protocol   = "-1"
    action     = "allow"
    cidr_block = var.cidr_block
    from_port  = 0
    to_port    = 0
  }

  # Return traffic for outbound connections (ephemeral ports), split around 3389 so RDP is never open.
  ingress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 3388
  }

  ingress {
    rule_no    = 105
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 3390
    to_port    = 65535
  }

  ingress {
    rule_no    = 110
    protocol   = "-1"
    action     = "allow"
    cidr_block = var.cidr_block
    from_port  = 0
    to_port    = 0
  }
}

# The NAT subnet forwards private traffic out and returns replies; nothing else.
resource "aws_network_acl" "public_nat" {
  # checkov:skip=CKV_AWS_231: The NAT gateway picks source ports from 1024-65535, so replies can arrive on 3389; closing it would break some outbound connections. Nothing in this subnet listens: it holds only the NAT gateway, which accepts no inbound connections.
  vpc_id     = aws_vpc.this.id
  subnet_ids = [aws_subnet.public_nat.id]
  tags       = merge(var.tags, { Name = "${var.name}-public-nat" })

  # From the private subnets to the NAT gateway.
  ingress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = var.cidr_block
    from_port  = 443
    to_port    = 443
  }

  # Replies from the internet to connections the NAT gateway opened.
  ingress {
    rule_no    = 110
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  egress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }

  # Replies from the NAT gateway back to the private subnets.
  egress {
    rule_no    = 110
    protocol   = "tcp"
    action     = "allow"
    cidr_block = var.cidr_block
    from_port  = 1024
    to_port    = 65535
  }
}

# Security group for the gateway tasks (stage S3): no ingress; HTTPS out only.
# Iridium's IP ranges are not known yet, so egress is any HTTPS destination through the NAT.
resource "aws_security_group" "gateway" {
  # checkov:skip=CKV2_AWS_5: Nothing runs in the VPC yet; the gateway tasks attach this group in stage S3.
  # checkov:skip=CKV_AWS_382: Egress is limited to TCP 443; Iridium's IWS address ranges are not published to us yet, so the destination cannot be narrowed below 0.0.0.0/0. Revisit when Iridium answers the allowlist question (re-plan §8.2).
  name        = "${var.name}-gateway"
  description = "IWS gateway: no inbound, HTTPS outbound only"
  vpc_id      = aws_vpc.this.id
  tags        = merge(var.tags, { Name = "${var.name}-gateway" })
}

resource "aws_vpc_security_group_egress_rule" "gateway_https" {
  security_group_id = aws_security_group.gateway.id
  description       = "HTTPS to IWS and AWS APIs"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

# VPC flow logs, encrypted, kept for a year.
resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/airtimesat/vpc/${var.name}/flow-logs"
  retention_in_days = var.flow_log_retention_days
  kms_key_id        = var.logs_kms_key_arn
  tags              = var.tags
}

data "aws_iam_policy_document" "flow_logs_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [aws_vpc.this.owner_id]
    }
  }
}

resource "aws_iam_role" "flow_logs" {
  name               = "${var.name}-flow-logs"
  assume_role_policy = data.aws_iam_policy_document.flow_logs_assume.json
  tags               = var.tags
}

data "aws_iam_policy_document" "flow_logs_write" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams",
    ]
    resources = ["${aws_cloudwatch_log_group.flow_logs.arn}:*"]
  }
}

resource "aws_iam_role_policy" "flow_logs" {
  name   = "write-flow-logs"
  role   = aws_iam_role.flow_logs.id
  policy = data.aws_iam_policy_document.flow_logs_write.json
}

resource "aws_flow_log" "this" {
  vpc_id                   = aws_vpc.this.id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn             = aws_iam_role.flow_logs.arn
  max_aggregation_interval = 600
  tags                     = var.tags
}
