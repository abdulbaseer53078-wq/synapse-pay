# Stateless app deployment in two regions (Stage 4, Step 17.4): the same images, one copy per region, each
# pointed at its own region's database and Kafka. Feed the load balancer outputs into infra/region-failover.
#
# Shared across regions: one AWS Private CA for terminal certificates (its CRL in S3 is read by every gateway)
# and a single STAN slot space (each card-service in either region gets its own slot).
#
# Standby workers stay at 0 until failover: after promoting the standby's database, set
# secondary.workers_desired = 1 (and run `python -m app.jobs audit-new-epoch` first, per Step 17.3).
#
# Apply with:  cd infra/ecs && terraform init && terraform apply

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.60" }
  }
}

variable "images" {
  type        = object({ api = string, card_service = string, gateway = string })
  description = "Image URIs (pin digests); built from backend/, card-service/ and gateway/ Dockerfiles"
}

variable "terminal_ca_arn" {
  type        = string
  description = "AWS Private CA that issues terminal certificates, shared by both regions"
}

variable "terminal_crl_url" {
  type        = string
  description = "Where that CA publishes its CRL (its S3 CRL distribution point, DER)"
}

variable "card_service_instances_per_region" {
  type    = number
  default = 1
}

variable "primary" {
  description = "The active region (e.g. ap-south-1): its network, certificate, database, Kafka and secrets."
  type = object({
    aws_region               = string
    vpc_id                   = string
    public_subnet_ids        = list(string)
    private_subnet_ids       = list(string)
    certificate_arn          = string
    database_url_secret_arn  = string
    kafka_bootstrap_servers  = string
    workers_desired          = number
    api_environment          = optional(map(string), {})
    api_secrets              = optional(map(string), {})
    card_service_environment = optional(map(string), {})
    card_service_secrets     = optional(map(string), {})
    gateway_secrets          = map(string)
    task_role_policy_arns    = optional(list(string), [])
  })
}

variable "secondary" {
  description = "The standby region (e.g. ap-south-2), set up the same way; workers_desired = 0 until promoted."
  type = object({
    aws_region               = string
    vpc_id                   = string
    public_subnet_ids        = list(string)
    private_subnet_ids       = list(string)
    certificate_arn          = string
    database_url_secret_arn  = string
    kafka_bootstrap_servers  = string
    workers_desired          = number
    api_environment          = optional(map(string), {})
    api_secrets              = optional(map(string), {})
    card_service_environment = optional(map(string), {})
    card_service_secrets     = optional(map(string), {})
    gateway_secrets          = map(string)
    task_role_policy_arns    = optional(list(string), [])
  })
}

provider "aws" {
  alias  = "primary"
  region = var.primary.aws_region
}

provider "aws" {
  alias  = "secondary"
  region = var.secondary.aws_region
}

locals {
  per_region     = var.card_service_instances_per_region
  stan_instances = 2 * local.per_region
}

module "primary" {
  source    = "./modules/region"
  providers = { aws = aws.primary }

  name                     = "synapsepay-${var.primary.aws_region}"
  images                   = var.images
  terminal_ca_arn          = var.terminal_ca_arn
  terminal_crl_url         = var.terminal_crl_url
  card_service_instances   = local.per_region
  stan_offset              = 0
  stan_instances           = local.stan_instances
  vpc_id                   = var.primary.vpc_id
  public_subnet_ids        = var.primary.public_subnet_ids
  private_subnet_ids       = var.primary.private_subnet_ids
  certificate_arn          = var.primary.certificate_arn
  database_url_secret_arn  = var.primary.database_url_secret_arn
  kafka_bootstrap_servers  = var.primary.kafka_bootstrap_servers
  workers_desired          = var.primary.workers_desired
  api_environment          = var.primary.api_environment
  api_secrets              = var.primary.api_secrets
  card_service_environment = var.primary.card_service_environment
  card_service_secrets     = var.primary.card_service_secrets
  gateway_secrets          = var.primary.gateway_secrets
  task_role_policy_arns    = var.primary.task_role_policy_arns
}

module "secondary" {
  source    = "./modules/region"
  providers = { aws = aws.secondary }

  name                     = "synapsepay-${var.secondary.aws_region}"
  images                   = var.images
  terminal_ca_arn          = var.terminal_ca_arn
  terminal_crl_url         = var.terminal_crl_url
  card_service_instances   = local.per_region
  stan_offset              = local.per_region # slots after the primary's: no STAN is ever minted twice
  stan_instances           = local.stan_instances
  vpc_id                   = var.secondary.vpc_id
  public_subnet_ids        = var.secondary.public_subnet_ids
  private_subnet_ids       = var.secondary.private_subnet_ids
  certificate_arn          = var.secondary.certificate_arn
  database_url_secret_arn  = var.secondary.database_url_secret_arn
  kafka_bootstrap_servers  = var.secondary.kafka_bootstrap_servers
  workers_desired          = var.secondary.workers_desired
  api_environment          = var.secondary.api_environment
  api_secrets              = var.secondary.api_secrets
  card_service_environment = var.secondary.card_service_environment
  card_service_secrets     = var.secondary.card_service_secrets
  gateway_secrets          = var.secondary.gateway_secrets
  task_role_policy_arns    = var.secondary.task_role_policy_arns
}

output "load_balancers" {
  description = "Inputs for infra/region-failover (regions.<name>.api_lb_* and terminal_lb_*)"
  value = {
    primary   = { api_lb_dns_name = module.primary.api_lb_dns_name, api_lb_zone_id = module.primary.api_lb_zone_id, terminal_lb_dns_name = module.primary.terminal_lb_dns_name, terminal_lb_zone_id = module.primary.terminal_lb_zone_id }
    secondary = { api_lb_dns_name = module.secondary.api_lb_dns_name, api_lb_zone_id = module.secondary.api_lb_zone_id, terminal_lb_dns_name = module.secondary.terminal_lb_dns_name, terminal_lb_zone_id = module.secondary.terminal_lb_zone_id }
  }
}
