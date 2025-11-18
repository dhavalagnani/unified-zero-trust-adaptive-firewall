# infra/terraform/main.tf
#
# Purpose: Main Terraform configuration for UZTAF infrastructure
# Context: This file defines the infrastructure as code for deploying UZTAF
#          components. Currently set up as a basic scaffold that can be
#          expanded based on specific cloud provider requirements.
#
# Usage: 
#   terraform init
#   terraform plan
#   terraform apply
#
# Note: This is a basic scaffold. Uncomment and customize sections based on
#       your target infrastructure (AWS, Azure, GCP, on-premises, etc.)

terraform {
  required_version = ">= 1.0"
  
  required_providers {
    # Uncomment the provider you need
    
    # aws = {
    #   source  = "hashicorp/aws"
    #   version = "~> 5.0"
    # }
    
    # azurerm = {
    #   source  = "hashicorp/azurerm"
    #   version = "~> 3.0"
    # }
    
    # google = {
    #   source  = "hashicorp/google"
    #   version = "~> 5.0"
    # }
  }
  
  # Backend configuration for state storage
  # Uncomment and configure based on your needs
  # backend "s3" {
  #   bucket = "uztaf-terraform-state"
  #   key    = "uztaf/terraform.tfstate"
  #   region = "us-east-1"
  # }
}

# Provider configuration
# Uncomment and configure based on your cloud provider

# provider "aws" {
#   region = var.aws_region
# }

# Variables
variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "project_name" {
  description = "Project name for resource tagging"
  type        = string
  default     = "uztaf"
}

# Example resource definitions (uncomment and customize)

# Virtual Network / VPC
# resource "aws_vpc" "uztaf_vpc" {
#   cidr_block           = "10.0.0.0/16"
#   enable_dns_hostnames = true
#   enable_dns_support   = true
#
#   tags = {
#     Name        = "${var.project_name}-vpc"
#     Environment = var.environment
#   }
# }

# Security Groups
# resource "aws_security_group" "pep_sg" {
#   name        = "${var.project_name}-pep-sg"
#   description = "Security group for PEP servers"
#   vpc_id      = aws_vpc.uztaf_vpc.id
#
#   ingress {
#     from_port   = 8000
#     to_port     = 8000
#     protocol    = "tcp"
#     cidr_blocks = ["0.0.0.0/0"]
#   }
#
#   egress {
#     from_port   = 0
#     to_port     = 0
#     protocol    = "-1"
#     cidr_blocks = ["0.0.0.0/0"]
#   }
# }

# Outputs
output "environment" {
  description = "Current environment"
  value       = var.environment
}

output "project_name" {
  description = "Project name"
  value       = var.project_name
}
