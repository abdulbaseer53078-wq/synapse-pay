# One region's copy of the stateless stack (Stage 4, Step 17.4), on ECS Fargate.
#
# Each API task runs three containers that share localhost:
#   api           FastAPI, behind the public ALB (merchants, SDKs, /health/region for Route 53)
#   card-service  loopback-only sidecar: unauthenticated and on the card-data path, so never on the network
#   gateway       Envoy, behind the NLB: terminals' mTLS, ext_authz against the api on 127.0.0.1:8000
# One ECS service per card-service STAN slot, all in the same target groups, so no two running card-services
# can mint the same STAN. Job workers run as separate services, and only where `workers_desired` > 0.

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.60" }
  }
}

variable "name" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "public_subnet_ids" {
  type = list(string)
}

variable "private_subnet_ids" {
  type        = list(string)
  description = "Need a NAT gateway: card-service reaches the acquirers through it, so the acquirer must allow its IPs."
}

variable "certificate_arn" {
  type        = string
  description = "ACM certificate in this region for the ALB (the API name and this region's health name)"
}

variable "images" {
  type = object({ api = string, card_service = string, gateway = string })
}

variable "database_url_secret_arn" {
  type        = string
  description = "Secrets Manager secret holding this region's DATABASE_URL"
}

variable "kafka_bootstrap_servers" {
  type        = string
  description = "This region's Kafka brokers"
}

variable "terminal_ca_arn" {
  type = string
}

variable "terminal_crl_url" {
  type = string
}

variable "stan_offset" {
  type        = number
  description = "First STAN slot of this region's card-services"
}

variable "stan_instances" {
  type        = number
  description = "STAN slots across every region"
}

variable "card_service_instances" {
  type = number
}

variable "workers_desired" {
  type        = number
  description = "1 where the database is writable (the primary); 0 in a standby, until it's promoted"
}

variable "api_environment" {
  type    = map(string)
  default = {}
}

variable "api_secrets" {
  type        = map(string)
  description = "Env var name => secret ARN. Use FILE_<NAME> for files (docker/write-secrets.sh)."
  default     = {}
}

variable "card_service_environment" {
  type    = map(string)
  default = {}
}

variable "card_service_secrets" {
  type    = map(string)
  default = {}
}

variable "gateway_secrets" {
  type        = map(string)
  description = "FILE_GATEWAY_CA, FILE_GATEWAY_SERVER_CERT, FILE_GATEWAY_SERVER_KEY"
}

variable "task_role_policy_arns" {
  type        = list(string)
  description = "Extra permissions for the app, e.g. the audit WORM bucket"
  default     = []
}

variable "jobs" {
  type    = list(string)
  default = ["relay-events", "audit-ingest", "audit-publish", "upi-poll"]
}

data "aws_region" "current" {}

locals {
  log_group  = "/synapsepay/${var.name}"
  slots      = { for i in range(var.card_service_instances) : tostring(i) => var.stan_offset + i }
  all_secret = concat([var.database_url_secret_arn], values(var.api_secrets), values(var.card_service_secrets), values(var.gateway_secrets))

  api_environment = merge(var.api_environment, {
    CARD_SERVICE_URL        = "http://127.0.0.1:7070"
    CA_BACKEND              = "aws_pca"
    AWS_PCA_ARN             = var.terminal_ca_arn
    KAFKA_BOOTSTRAP_SERVERS = var.kafka_bootstrap_servers
  })
  api_secrets = merge(var.api_secrets, { DATABASE_URL = var.database_url_secret_arn })

  logs = {
    logDriver = "awslogs"
    options = {
      awslogs-group         = local.log_group
      awslogs-region        = data.aws_region.current.name
      awslogs-stream-prefix = "app"
    }
  }
}

# ECS wants [{name, value}] / [{name, valueFrom}] lists, not maps.
locals {
  env     = { for k, m in { api = local.api_environment, card = var.card_service_environment } : k => [for n, v in m : { name = n, value = v }] }
  secrets = { for k, m in { api = local.api_secrets, card = var.card_service_secrets, gateway = var.gateway_secrets } : k => [for n, v in m : { name = n, valueFrom = v }] }
}

resource "aws_cloudwatch_log_group" "app" {
  name              = local.log_group
  retention_in_days = 90
}

# --- IAM -------------------------------------------------------------------------------------------------------

data "aws_iam_policy_document" "ecs_tasks" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "execution" {
  name               = "${var.name}-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks.json
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "execution_secrets" {
  name = "read-secrets"
  role = aws_iam_role.execution.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = distinct(local.all_secret) }]
  })
}

resource "aws_iam_role" "task" {
  name               = "${var.name}-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks.json
}

resource "aws_iam_role_policy" "task_terminal_ca" {
  name = "terminal-ca"
  role = aws_iam_role.task.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["acm-pca:IssueCertificate", "acm-pca:GetCertificate", "acm-pca:RevokeCertificate", "acm-pca:GetCertificateAuthorityCertificate"]
      Resource = var.terminal_ca_arn
    }]
  })
}

resource "aws_iam_role_policy_attachment" "task_extra" {
  for_each   = toset(var.task_role_policy_arns)
  role       = aws_iam_role.task.name
  policy_arn = each.value
}

# --- Network ---------------------------------------------------------------------------------------------------

resource "aws_security_group" "alb" {
  name   = "${var.name}-alb"
  vpc_id = var.vpc_id
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "tasks" {
  name   = "${var.name}-tasks"
  vpc_id = var.vpc_id
  ingress {
    description     = "API, from the ALB only"
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  ingress {
    description = "Terminal mTLS through the NLB, which keeps client IPs. Envoy rejects anything without a valid certificate."
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_lb" "api" {
  name               = "${var.name}-api"
  load_balancer_type = "application"
  subnets            = var.public_subnet_ids
  security_groups    = [aws_security_group.alb.id]
}

resource "aws_lb_target_group" "api" {
  name        = "${var.name}-api"
  port        = 8000
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = var.vpc_id
  health_check {
    # Liveness only. /health/region is DOWN in an unpromoted standby by design; using it here would make ECS
    # kill and replace the standby's tasks forever.
    path = "/health/live"
  }
}

resource "aws_lb_listener" "api" {
  load_balancer_arn = aws_lb.api.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}

resource "aws_lb" "terminals" {
  name               = "${var.name}-terminals"
  load_balancer_type = "network"
  subnets            = var.public_subnet_ids
}

resource "aws_lb_target_group" "terminals" {
  name        = "${var.name}-terminals"
  port        = 8443
  protocol    = "TCP" # TLS passes through to Envoy, which does the mutual TLS
  target_type = "ip"
  vpc_id      = var.vpc_id
}

resource "aws_lb_listener" "terminals" {
  load_balancer_arn = aws_lb.terminals.arn
  port              = 8443
  protocol          = "TCP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.terminals.arn
  }
}

# --- Services --------------------------------------------------------------------------------------------------

resource "aws_ecs_cluster" "this" {
  name = var.name
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_ecs_task_definition" "api" {
  for_each                 = local.slots
  family                   = "${var.name}-api-${each.key}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 1024
  memory                   = 2048
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn
  container_definitions = jsonencode([
    {
      name             = "api"
      image            = var.images.api
      essential        = true
      portMappings     = [{ containerPort = 8000 }]
      environment      = local.env.api
      secrets          = local.secrets.api
      logConfiguration = local.logs
    },
    {
      name      = "card-service"
      image     = var.images.card_service
      essential = true
      environment = concat(local.env.card, [
        { name = "STAN_INSTANCE", value = tostring(each.value) },
        { name = "STAN_INSTANCES", value = tostring(var.stan_instances) },
        { name = "AUDIT_LOG_PATH", value = "/dev/stdout" }, # redacted ISO 8583 records, kept by CloudWatch Logs
      ])
      secrets          = local.secrets.card
      logConfiguration = local.logs
    },
    {
      name             = "gateway"
      image            = var.images.gateway
      essential        = true
      portMappings     = [{ containerPort = 8443 }]
      environment      = [{ name = "GATEWAY_CRL_URL", value = var.terminal_crl_url }]
      secrets          = local.secrets.gateway
      logConfiguration = local.logs
    },
  ])
}

resource "aws_ecs_service" "api" {
  for_each        = local.slots
  name            = "api-${each.key}"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.api[each.key].arn
  launch_type     = "FARGATE"
  desired_count   = 1
  # Stop the old task before starting the new one: overlapping would put two card-services on one STAN slot.
  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 100

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.tasks.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.api.arn
    container_name   = "api"
    container_port   = 8000
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.terminals.arn
    container_name   = "gateway"
    container_port   = 8443
  }

  depends_on = [aws_lb_listener.api, aws_lb_listener.terminals]
}

locals {
  # refresh-health runs once per invocation and should repeat every 30 s.
  job_commands = merge(
    { for job in var.jobs : job => ["python", "-m", "app.jobs", job] },
    { "refresh-health" = ["sh", "-c", "while :; do python -m app.jobs refresh-health; sleep 30; done"] },
  )
}

resource "aws_ecs_task_definition" "job" {
  for_each                 = local.job_commands
  family                   = "${var.name}-job-${each.key}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn
  container_definitions = jsonencode([{
    name             = "job"
    image            = var.images.api
    essential        = true
    command          = each.value
    environment      = local.env.api
    secrets          = local.secrets.api
    logConfiguration = local.logs
  }])
}

resource "aws_ecs_service" "job" {
  for_each        = local.job_commands
  name            = "job-${each.key}"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.job[each.key].arn
  launch_type     = "FARGATE"
  # 0 in a standby: an audit-ingest against an unpromoted replica would extend the chain the primary owns.
  desired_count = var.workers_desired

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.tasks.id]
    assign_public_ip = false
  }
}

output "api_lb_dns_name" {
  value = aws_lb.api.dns_name
}

output "api_lb_zone_id" {
  value = aws_lb.api.zone_id
}

output "terminal_lb_dns_name" {
  value = aws_lb.terminals.dns_name
}

output "terminal_lb_zone_id" {
  value = aws_lb.terminals.zone_id
}
