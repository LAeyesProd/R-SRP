# R-SRP Ultra Multi-Cloud Infrastructure
# Supports: AWS, Azure, GCP, On-Prem

# ============================================================================
# VARIABLES
# ============================================================================

variable "cloud_provider" {
  description = "Cloud provider: aws, azure, gcp, or onprem"
  type        = string
  default     = "aws"
  
  validation {
    condition     = contains(["aws", "azure", "gcp", "onprem"], var.cloud_provider)
    error_message = "Cloud provider must be one of: aws, azure, gcp, onprem"
  }
}

variable "environment" {
  description = "Environment: dev, staging, prod"
  type        = string
  default     = "prod"
}

variable "region" {
  description = "Region for deployment"
  type        = string
  default     = "eu-west-1"
}

variable "cluster_name" {
  description = "Name of the Kubernetes cluster"
  type        = string
  default     = "rsrp-ultra"
}

variable "admin_authorized_ip_ranges" {
  description = "Authorized CIDR ranges for Kubernetes API access (AKS)"
  type        = list(string)
  default     = ["10.0.0.0/8"]

  validation {
    condition = length(var.admin_authorized_ip_ranges) > 0 && alltrue([
      for cidr in var.admin_authorized_ip_ranges : can(cidrhost(cidr, 0)) && cidr != "0.0.0.0/0"
    ])
    error_message = "admin_authorized_ip_ranges must contain at least one valid CIDR and must not include 0.0.0.0/0"
  }
}

variable "gke_pods_secondary_range_name" {
  description = "Secondary subnet range name used for GKE Pods (Alias IP)"
  type        = string
  default     = "gke-pods"
}

variable "gke_services_secondary_range_name" {
  description = "Secondary subnet range name used for GKE Services (Alias IP)"
  type        = string
  default     = "gke-services"
}

variable "high_availability" {
  description = "Enable high availability mode"
  type        = bool
  default     = true
}

# ============================================================================
# KUBERNETES CLUSTER
# ============================================================================

# AWS EKS
resource "aws_eks_cluster" "rsrp" {
  count = var.cloud_provider == "aws" ? 1 : 0
  name     = var.cluster_name
  role_arn = aws_iam_role.eks_cluster.arn
  version  = "1.29"

  vpc_config {
    subnet_ids = var.subnet_ids
    endpoint_private_access = true
    endpoint_public_access  = false  # Private cluster only
  }

  # Enable EKS cluster security
  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  # Encryption at rest
  encryption_config {
    resources = ["secrets"]
    provider {
      key_arn = aws_kms_key.eks_key.arn
    }
  }

  # Enable control plane logging
  kubernetes_network_config {
    ip_family         = "ipv4"
    service_ipv4_cidr = "10.96.0.0/12"
  }

  tags = {
    Environment = var.environment
    CloudProvider = "aws"
  }
}

# Azure AKS
resource "azurerm_kubernetes_cluster" "rsrp" {
  count = var.cloud_provider == "azure" ? 1 : 0
  name                = var.cluster_name
  location            = var.region
  resource_group_name = azurerm_resource_group.rsrp.name
  dns_prefix          = "rsrp"
  kubernetes_version   = "1.29"
  private_cluster_enabled = true
  local_account_disabled  = true

  # RBAC enabled
  role_based_access_control_enabled = true
  azure_active_directory_role_based_access_control {
    managed                = true
    azure_rbac_enabled     = true
  }

  # Network configuration
  network_profile {
    network_plugin     = "azure"
    network_policy     = "calico"
    load_balancer_sku  = "standard"
  }

  api_server_access_profile {
    authorized_ip_ranges = var.admin_authorized_ip_ranges
  }

  # Secret encryption
  secret_rotation_enabled = true

  # Addons
  oms_agent {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
    msi_auth_for_monitoring_enabled = true
  }

  tags = {
    Environment  = var.environment
    CloudProvider = "azure"
  }
}

# GCP GKE
# snyk:ignore:SNYK-CC-TF-88 PodSecurityPolicy is removed in Kubernetes 1.25+.
# The cluster uses GKE 1.29 with Pod Security Admission and policy enforcement via Kyverno.
resource "google_container_cluster" "rsrp" {
  count = var.cloud_provider == "gcp" ? 1 : 0
  name     = var.cluster_name
  location = var.region

  # Release channel
  release_channel {
    channel = "STABLE"
  }

  # Required for secure VPC-native GKE networking (Alias IP ranges)
  ip_allocation_policy {
    cluster_secondary_range_name  = var.gke_pods_secondary_range_name
    services_secondary_range_name = var.gke_services_secondary_range_name
  }

  resource_labels = {
    environment      = var.environment
    cloud_provider   = "gcp"
    security_profile = "hardened"
    managed_by       = "terraform"
  }

  # Network security
  network_policy {
    enabled = true
  }

  # Encryption
  database_encryption {
    state    = "ENCRYPTED"
    key_name = google_kms_crypto_key.rsrp_key.id
  }

  # Workload identity
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  # Private cluster - no public endpoint
  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = true
    master_ipv4_cidr_block = "10.64.0.0/28"
  }

  # Disable client certificates - use OAuth instead
  master_auth {
    username = ""
    password = ""

    client_certificate_config {
      issue_client_certificate = false
    }
  }

  # Enable master authorized networks for admin access only
  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = var.admin_cidr
      display_name = "Admin Network"
    }
  }

  enable_shielded_nodes = true
  shielded_instance_config {
    enable_secure_boot          = true
    enable_integrity_monitoring = true
  }
}

# ============================================================================
# NODE POOLS
# ============================================================================

# System nodes (critical infrastructure)
resource "aws_eks_node_group" "system" {
  cluster_name = aws_eks_cluster.rsrp[0].name
  node_group_name = "system"
  
  instance_types = ["m6i.xlarge"]
  capacity_type  = "ON_DEMAND"
  
  scaling_config {
    desired_size = 3
    min_size     = 3
    max_size     = 6
  }

  # Labels for system workloads
  labels = {
    "node-role" = "system"
    "critical"  = "true"
  }

  # Taints for system pods only
  taint {
    key    = "node-role"
    value  = "system"
    effect = "NO_SCHEDULE"
  }
}

# Application nodes
resource "aws_eks_node_group" "application" {
  cluster_name = aws_eks_cluster.rsrp[0].name
  node_group_name = "application"
  
  instance_types = ["m6i.2xlarge"]
  capacity_type  = "ON_DEMAND"
  
  scaling_config {
    desired_size = 6
    min_size     = 3
    max_size     = 20
  }

  labels = {
    "node-role" = "application"
  }
}

# Database nodes (for immutablelogging)
resource "aws_eks_node_group" "database" {
  cluster_name = aws_eks_cluster.rsrp[0].name
  node_group_name = "database"
  
  instance_types = ["r6i.2xlarge"]
  capacity_type  = "ON_DEMAND"
  
  scaling_config {
    desired_size = 3
    min_size     = 3
    max_size     = 6
  }

  labels = {
    "node-role" = "database"
  }

  taint {
    key    = "node-role"
    value  = "database"
    effect = "NO_SCHEDULE"
  }
}

# ============================================================================
# SECURITY - KMS KEYS
# ============================================================================

# EKS Encryption Key
resource "aws_kms_key" "eks_key" {
  description             = "R-SRP EKS encryption key"
  deletion_window_in_days = 10
  enable_key_rotation    = true
  
  tags = {
    Environment = var.environment
    Purpose     = "EKS-Encryption"
  }
}

# Secrets Manager Key
resource "aws_kms_key" "secrets_key" {
  description             = "R-SRP Secrets encryption key"
  deletion_window_in_days = 10
  enable_key_rotation    = true
  
  tags = {
    Environment = var.environment
    Purpose     = "Secrets-Encryption"
  }
}

# Database Key
resource "aws_kms_key" "database_key" {
  description             = "R-SRP Database encryption key"
  deletion_window_in_days = 10
  enable_key_rotation    = true
  
  tags = {
    Environment = var.environment
    Purpose     = "Database-Encryption"
  }
}

# ============================================================================
# NETWORK - VPC
# ============================================================================

resource "aws_vpc" "rsrp" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "rsrp-vpc"
    Environment = var.environment
  }
}

# Private Subnets
resource "aws_subnet" "private" {
  count             = 3
  vpc_id            = aws_vpc.rsrp.id
  cidr_block       = "10.0.${count.index + 1}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "rsrp-private-${count.index + 1}"
  }
}

# Public Subnets
resource "aws_subnet" "public" {
  count             = 3
  vpc_id            = aws_vpc.rsrp.id
  cidr_block       = "10.0.${count.index + 10}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "rsrp-public-${count.index + 1}"
  }
}

# ============================================================================
# NETWORK POLICIES - CILIUM
# ============================================================================

# Cilium installation via Helm
resource "helm_release" "cilium" {
  name       = "cilium"
  repository = "https://helm.cilium.io"
  chart      = "cilium"
  version    = "1.14.0"

  set {
    name  = "cni.mode"
    value = "cilium"
  }

  set {
    name  = "ipam.mode"
    value = "cluster-scope"
  }

  set {
    name  = "hubble.enabled"
    value = "true"
  }

  set {
    name  = "hubble.ui.enabled"
    value = "true"
  }

  set {
    name  = "encryption.enabled"
    value = "true"
  }

  set {
    name  = "encryption.type"
    value = "wireguard"
  }
}

# ============================================================================
# SECURE RUNTIME - FALCO
# ============================================================================

resource "helm_release" "falco" {
  name       = "falco"
  repository = "https://falcosecurity.github.io/charts"
  chart      = "falco"
  version    = "4.0.0"

  set {
    name  = "driver.kind"
    value = "ebpf"
  }

  set {
    name  = "falcoctl.artifact.install.enabled"
    value = "true"
  }

  set {
    name  = "prometheus.enabled"
    value = "true"
  }

  set {
    name  = "tetragon.enabled"
    value = "true"
  }
}

# ============================================================================
# ADMISSION CONTROL - KYVERNO
# ============================================================================

resource "helm_release" "kyverno" {
  name       = "kyverno"
  repository = "https://kyverno.github.io/kyverno"
  chart      = "kyverno"
  version    = "3.0.0"

  set {
    name  = "config.excludeKind"
    value = "System:*"
  }

  set {
    name  = "admissionController.replicas"
    value = "3"
  }

  set {
    name  = ".rebackgroundControllerplicas"
    value = "2"
  }

  set {
    name  = "cleanupController.replicas"
    value = "2"
  }

  set {
    name  = "reportsController.replicas"
    value = "2"
  }
}

# ============================================================================
# SECRETS MANAGEMENT - HASHICORP VAULT
# ============================================================================

resource "helm_release" "vault" {
  name       = "vault"
  repository = "https://helm.releases.hashicorp.com"
  chart      = "vault"
  version    = "0.27.0"

  set {
    name  = "server.dev.enabled"
    value = "false"
  }

  set {
    name  = "server.ha.enabled"
    value = "true"
  }

  set {
    name  = "server.ha.replicas"
    value = "3"
  }

  set {
    name  = "server.raft.enabled"
    value = "true"
  }

  # Inject CA for TLS
  set {
    name  = "server.extraVolumes[0].type"
    value = "secret"
  }
}

# ============================================================================
# OUTPUTS
# ============================================================================

output "cluster_endpoint" {
  description = "Kubernetes cluster endpoint"
  value       = var.cloud_provider == "aws" ? aws_eks_cluster.rsrp[0].endpoint : ""
}

output "cluster_name" {
  description = "Kubernetes cluster name"
  value       = var.cluster_name
}

output "kms_key_arns" {
  description = "KMS key ARNs for encryption"
  value = {
    eks     = aws_kms_key.eks_key.arn
    secrets = aws_kms_key.secrets_key.arn
    database = aws_kms_key.database_key.arn
  }
}

output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.rsrp.id
}

output "private_subnet_ids" {
  description = "Private subnet IDs"
  value       = aws_subnet.private[*].id
}

# ============================================================================
# DATA SOURCES
# ============================================================================

data "aws_availability_zones" "available" {
  state = "available"
}
