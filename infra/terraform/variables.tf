# infra/terraform/variables.tf
#
# Purpose: Define input variables for Terraform configuration
# Context: Centralized variable definitions for the UZTAF infrastructure
#
# Usage: Set values in terraform.tfvars or via command line:
#        terraform apply -var="environment=prod"

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
  
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "project_name" {
  description = "Project name for resource naming and tagging"
  type        = string
  default     = "uztaf"
}

variable "aws_region" {
  description = "AWS region for resource deployment"
  type        = string
  default     = "us-east-1"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "instance_type" {
  description = "EC2 instance type for UZTAF components"
  type        = string
  default     = "t3.medium"
}

variable "ssh_key_name" {
  description = "Name of SSH key pair for instance access"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default = {
    Project   = "UZTAF"
    ManagedBy = "Terraform"
  }
}
