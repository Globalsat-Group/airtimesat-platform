output "vpc_id" {
  description = "ID of the gateway VPC."
  value       = aws_vpc.this.id
}

output "private_subnet_ids" {
  description = "IDs of the private subnets where the gateway runs."
  value       = aws_subnet.private[*].id
}

output "gateway_security_group_id" {
  description = "ID of the gateway security group (no ingress, HTTPS egress)."
  value       = aws_security_group.gateway.id
}

output "nat_egress_ip" {
  description = "Fixed public egress IP. Give it to Iridium for the IP allowlist (re-plan §8.2) and use it in ST-15."
  value       = aws_eip.nat.public_ip
}
