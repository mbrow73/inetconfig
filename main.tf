# Configure the Google provider (authenticate and set project)
provider "google" {
  project     = var.project_id
  region      = var.region
  credentials = var.credentials
}

#### 1) Slurp in every JSON request file ####
data "local_file" "requests" {
  for_each = fileset(path.module, "firewall_requests/*.json")
  filename = "${path.module}/${each.value}"
}

#### 2) Decode + flatten into the shape your module needs ####
locals {
  auto_firewall_rules = flatten([
    for req_file in data.local_file.requests : [
      for idx, r in jsondecode(req_file.content).rules : {
        name                   = "AUTO-${upper(jsondecode(req_file.content).carid)}-${r.request_id_reqid}-${idx+1}-${upper(r.protocol)}-${replace(r.port_s, ",", "-")}"
        description            = r.business_justification
        priority               = 1000 + idx
        direction              = upper(r.direction)
        action                 = "allow"
        enable_logging         = true
        src_ip_ranges          = split(",", r.source_ip_s_or_cidr_s)
        dest_ip_ranges         = split(",", r.destination_ip_s_or_cidr_s)
        protocol               = upper(r.protocol)
        ports                  = split(",", r.port_s)
        tls_inspect            = false
      }
    ]
  ])

  inet_firewall_rules = concat(
    local.auto_firewall_rules,
    var.manual_firewall_rules
  )
}

# Module: CA (Private CA pool and CA)
#module "ca" {
#  source          = "./modules/ca"
#  project_id      = var.project_id
#  location        = var.region         # e.g., "us-central1"
#  ca_pool_name    = "${var.env}-ca-pool"
#  ca_name         = "${var.env}-root-ca"
#  ca_common_name  = "${var.env} Environment TLS CA"    # e.g., "DEV Environment TLS CA"
#  ca_organization = var.ca_organization
#  ca_country      = var.ca_country_code
#}

# Module: TLS Inspection (Policy & Trust Config)
#module "tls" {
#  source               = "./modules/tls_inspection"
#  project_id           = var.project_id
#  location             = var.region
#  tls_policy_name      = "${var.env}-inet-tls-policy"
#  trust_config_name    = "${var.env}-inet-trust-config"
#  ca_pool_id           = module.ca.ca_pool_id    # input from CA module output
#  trust_anchor_cert    = var.trust_anchor_cert
#  intermediate_ca_cert = var.intermediate_ca_cert
#}

# Module: Security Profiles (IPS/AV and group)
#module "security_profiles" {
#  source              = "./modules/security_profiles"
#  ips_profile_name    = "${var.env}-ips-profile"
#  av_profile_name     = "${var.env}-av-profile"
#  profile_group_name  = "${var.env}-profiles-group"
#  org_id              = var.org_id
#}

# Module: NGFW Endpoint (firewall endpoint and association)
#module "ngfw_endpoint" {
#  source             = "./modules/firewall_endpoint"
#  billing_project_id = var.billing_project_id
#  org_id             = var.org_id
#  endpoint_name      = "${var.env}-ngfw-endpoint"
#  zone               = var.zone               # e.g., "us-central1-a"
#  vpc_network_id     = var.vpc_network_id
#  tls_policy_id      = module.tls.tls_policy_id
#}


module "inet_firewall_policy" {
  source                    = "./modules/firewall_policy"
  project_id                = var.project_id
  inet_vpc                  = "projects/meta-episode-463418-i2/global/networks/default"
  security_profile_group_id = ""
  policy_name               = "inet-policy"
  inet_firewall_rules       = local.inet_firewall_rules
}
