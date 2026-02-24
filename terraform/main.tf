# R-SRP Ultra - Terraform Infrastructure Configuration
# Kubernetes cluster and services

terraform {
  required_version = ">= 1.6"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
    }
  }
  
  backend "s3" {
    bucket = "rsrp-terraform-state"
    key    = "production/terraform.tfstate"
    region = "eu-west-1"
  }
}

# Provider configuration
provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = "R-SRP"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# Variables
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "eu-west-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "cluster_name" {
  description = "EKS cluster name"
  type        = string
  default     = "rsrp-eks"
}

# EKS Cluster
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 19.0"
  
  cluster_name    = var.cluster_name
  cluster_version = "1.28"
  
  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets
  
  # EKS Managed Node Group
  eks_managed_node_groups = {
    primary = {
      name           = "primary"
      instance_types = ["m6i.xlarge"]
      capacity_type  = "ON_DEMAND"
      
      min_size     = 3
      max_size     = 10
      desired_size = 3
      
      labels = {
        tier = "application"
      }
      
      tags = {
        "k8s.amazonaws.com/enableLaunch" = "ON_DEMAND"
      }
    }
Type    
    critical = {
      name           = "critical"
      instance_types = ["m6i.2xlarge"]
      capacity_type  = "ON_DEMAND"
      
      min_size     = 3
      max_size     = 6
      desired_size = 3
      
      labels = {
        tier = "critical"
      }
      
      tags = {
        "k8s.amazonaws.com/enableLaunchType" = "ON_DEMAND"
      }
    }
  }
  
  tags = {
    Environment = var.environment
    Project    = "R-SRP"
  }
}

# VPC Configuration
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"
  
  name = "rsrp-vpc"
  
  cidr = "10.0.0.0/16"
  
  azs                 = ["${var.aws_region}a", "${var.aws_region}b", "${var.aws_region}c"]
  private_subnets     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets      = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
  database_subnets    = ["10.0.201.0/24", "10.0.202.0/24", "10.0.203.0/24"]
  
  enable_nat_gateway     = true
  single_nat_gateway     = false
  one_nat_gateway_per_az = true
  
  tags = {
    Environment = var.environment
    Project    = "R-SRP"
  }
}

# Kubernetes Provider
provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", var.cluster_name]
  }
}

# Helm Provider
provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
    
    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", var.cluster_name]
    }
  }
}

# Namespace
resource "kubernetes_namespace" "rsrp" {
  metadata {
    name = "rsrp"
    
    labels = {
      "istio-injection" = "enabled"
    }
  }
}

# Helm Release - API Service
resource "helm_release" "api_service" {
  name       = "rsrp-api"
  namespace  = kubernetes_namespace.rsrp.metadata[0].name
  chart      = "../charts/rsrp-api"
  version    = "1.0.0"
  wait       = true
  
  set {
    name  = "image.tag"
    value = "1.0.0"
  }
  
  set {
    name  = "replicaCount"
    value = "3"
  }
  
  set {
    name  = "ingress.enabled"
    value = "true"
  }
}

# Outputs
output "cluster_endpoint" {
  value = module.eks.cluster_endpoint
}

output "cluster_name" {
  value = module.eks.cluster_name
}
