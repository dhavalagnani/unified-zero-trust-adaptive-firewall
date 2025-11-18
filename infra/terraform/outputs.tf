# infra/terraform/outputs.tf
#
# Purpose: Define output values from Terraform deployment
# Context: Outputs useful information after infrastructure deployment
#          such as IP addresses, DNS names, and connection strings
#
# Usage: After 'terraform apply', view outputs with:
#        terraform output

output "environment" {
  description = "Deployed environment name"
  value       = var.environment
}

output "project_name" {
  description = "Project identifier"
  value       = var.project_name
}

output "deployment_timestamp" {
  description = "Timestamp of deployment"
  value       = timestamp()
}

# Example outputs for when resources are created
# Uncomment and customize based on your infrastructure

# output "vpc_id" {
#   description = "ID of the VPC"
#   value       = aws_vpc.uztaf_vpc.id
# }

# output "pep_server_ips" {
#   description = "IP addresses of PEP servers"
#   value       = aws_instance.pep[*].public_ip
# }

# output "correlation_server_ip" {
#   description = "IP address of correlation engine server"
#   value       = aws_instance.correlation.public_ip
# }

# output "keycloak_url" {
#   description = "URL for Keycloak identity server"
#   value       = "http://${aws_instance.keycloak.public_ip}:8080"
# }
