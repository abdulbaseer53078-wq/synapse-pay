# Region failover (Stage 4, Step 17.1): Route 53 sends all traffic to the primary region (e.g. Mumbai) and
# switches to the standby (e.g. Hyderabad) when the primary's health check fails.
#
# Failover, not active-active: exactly one region writes at a time. If both took payments, the same
# idempotency_key could create a transaction in each region and charge the customer twice.
#
# Health: every 10 s, each region's GET /health/region (backend/app/api/region.py) answers UP only if that
# region's database is the writable primary and card-service has an acquirer that can take traffic. 3 failures
# (30 s) mark a region unhealthy. What a primary outage looks like:
#   1. Primary fails its check. The standby is still DOWN too: its Aurora Global Database secondary is read-only.
#      With every region unhealthy, Route 53 keeps answering with the primary.
#   2. The alarm below pages on-call, who promotes the standby (aws rds failover-global-cluster, or Aurora's
#      managed unplanned failover).
#   3. The standby's database is now writable, its check turns UP, and DNS moves traffic there.
# Clients see the change after the record's TTL (60 s for load balancer aliases) plus their own DNS caching.
#
# Inputs are the per-region load balancers, which don't exist in this repo yet (nothing is deployed). Apply with:
#   cd infra/region-failover && terraform init && terraform apply
# Not run by the test suite.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.60" }
  }
}

# Route 53 publishes health-check metrics only in us-east-1, so the alarms live there.
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

variable "zone_id" {
  type        = string
  description = "Route 53 hosted zone for the public names"
}

variable "api_name" {
  type        = string
  description = "The name merchants, SDKs and the checkout call, e.g. api.synapsepay.in"
}

variable "terminal_name" {
  type        = string
  description = "The name terminals connect to over mTLS (the Envoy gateway), e.g. terminals.synapsepay.in. Null: no terminal record."
  default     = null
}

variable "regions" {
  description = "Exactly two regions, keyed by name (e.g. ap-south-1, ap-south-2): one PRIMARY, one SECONDARY."
  type = map(object({
    role                 = string # PRIMARY | SECONDARY
    health_fqdn          = string # region-specific API name with a valid TLS certificate, e.g. api-ap-south-1.synapsepay.in
    api_lb_dns_name      = string
    api_lb_zone_id       = string
    terminal_lb_dns_name = optional(string) # the region's mTLS gateway load balancer, when terminal_name is set
    terminal_lb_zone_id  = optional(string)
  }))

  validation {
    condition     = length(var.regions) == 2 && sort([for r in values(var.regions) : r.role]) == ["PRIMARY", "SECONDARY"]
    error_message = "regions must hold exactly two entries, one with role PRIMARY and one with role SECONDARY."
  }
}

variable "alarm_sns_topic_arn" {
  type        = string
  description = "SNS topic in us-east-1 that pages on-call when a region fails its health check. Null: no alarm."
  default     = null
}

resource "aws_route53_health_check" "region" {
  for_each          = var.regions
  type              = "HTTPS"
  fqdn              = each.value.health_fqdn
  port              = 443
  resource_path     = "/health/region"
  enable_sni        = true
  request_interval  = 10 # fast checks
  failure_threshold = 3  # 3 x 10 s = 30 s before a region is failed

  tags = { Name = "synapsepay-${each.key}" }
}

resource "aws_route53_record" "api" {
  for_each        = var.regions
  zone_id         = var.zone_id
  name            = var.api_name
  type            = "A"
  set_identifier  = each.key
  health_check_id = aws_route53_health_check.region[each.key].id

  failover_routing_policy {
    type = each.value.role
  }

  alias {
    name                   = each.value.api_lb_dns_name
    zone_id                = each.value.api_lb_zone_id
    evaluate_target_health = true
  }
}

# Terminals follow the same region as the API. The mTLS gateway can't be probed directly (Route 53 has no client
# certificate), and a terminal sent to a region that can't take payments would only queue offline anyway.
resource "aws_route53_record" "terminals" {
  for_each        = var.terminal_name == null ? {} : var.regions
  zone_id         = var.zone_id
  name            = var.terminal_name
  type            = "A"
  set_identifier  = each.key
  health_check_id = aws_route53_health_check.region[each.key].id

  failover_routing_policy {
    type = each.value.role
  }

  alias {
    name                   = each.value.terminal_lb_dns_name
    zone_id                = each.value.terminal_lb_zone_id
    evaluate_target_health = true
  }

  lifecycle {
    precondition {
      condition     = each.value.terminal_lb_dns_name != null && each.value.terminal_lb_zone_id != null
      error_message = "terminal_name is set, so every region needs terminal_lb_dns_name and terminal_lb_zone_id."
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "region_unhealthy" {
  for_each            = var.alarm_sns_topic_arn == null ? {} : var.regions
  provider            = aws.us_east_1
  alarm_name          = "synapsepay-region-${each.key}-unhealthy"
  alarm_description   = "${each.key} (${each.value.role}) can't take payments. If it's the primary, promote the standby's Aurora secondary so DNS can fail over."
  namespace           = "AWS/Route53"
  metric_name         = "HealthCheckStatus"
  dimensions          = { HealthCheckId = aws_route53_health_check.region[each.key].id }
  statistic           = "Minimum"
  period              = 60
  evaluation_periods  = 1
  comparison_operator = "LessThanThreshold"
  threshold           = 1
  treat_missing_data  = "breaching" # no data from the checkers is not good news
  alarm_actions       = [var.alarm_sns_topic_arn]
  ok_actions          = [var.alarm_sns_topic_arn]
}

output "health_check_ids" {
  value = { for name, check in aws_route53_health_check.region : name => check.id }
}
