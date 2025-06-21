#variable "env" {
#  description = "Environment name (e.g., dev, prod)"
#  type        = string
#  default     = "dev"
#}
#
#variable "org_id" {
#  description = "GCP organization ID"
#  type        = string
#  default     = ""
#}

#variable "trust_anchor_cert" {
#  description = "Trust anchor certificate for TLS inspection"
#  type        = string
#}
#
#variable "intermediate_ca_cert" {
#  description = "Trust anchor certificate for TLS inspection"
#  type        = string
#}

variable "project_id" {
  description = "GCP project ID for the TLS inspection policy"
  type        = string
  default     = "meta-episode-463418-i2"
}

variable "vpc_network_id" {
  description = "The VPC network (self-link or ID) to attach the endpoint to"
  type        = string
  default     = ""
}

variable "zone" {
  description = "Zone for the firewall endpoint (must match zone of workloads)"
  type        = string
  default     = ""
}

variable "billing_project_id" {
  description = "Billing project ID for the NGFW endpoint"
  type        = string
  default     = ""
}

variable "region" {
  description = "Region for the TLS inspection policy (must be same as CA region)"
  type        = string
  default     = "us-central1"
}

variable "ca_organization" {
  description = "Organization name for the CA"
  type        = string
  default     = ""
}

variable "ca_country_code" {
  description = "Country code for the CA"
  type        = string
  default     = "US"
}


variable "inet_firewall_rules" {
  description = <<-EOT
    A list of firewall‐policy rules to create.  
    Each object must include:
      - name                   = unique name for the rule  
      - description            = human description  
      - priority               = rule priority (lower = higher match)  
      - direction              = "INGRESS" or "EGRESS"  
      - action                 = one of ["allow","deny","apply_security_profile_group"]  
      - security_profile_group = (if action == "apply_security_profile_group")  
      - enable_logging         = bool  
      - src_ip_ranges          = list(string)  
      - dest_ip_ranges         = list(string)  
      - ports                  = list(string)  # layer4 ports  
      - tls_inspection         = bool           # whether to decrypt TLS  
  EOT
  type = list(object({
    name                   = string
    description            = string
    priority               = number
    direction              = string
    action                 = string
    security_profile_group = optional(string)
    enable_logging         = bool
    src_ip_ranges          = list(string)
    dest_ip_ranges         = list(string)
    ports                  = list(string)
    protocol               = string
    tls_inspection         = bool
  }))
}
variable "credentials" {
  description = "Path to the service account credentials JSON file"
  type        = string
  default     = ""
}