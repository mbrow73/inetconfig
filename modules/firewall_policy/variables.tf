variable "project_id" {
  description = "GCP project ID for the firewall policy"
  type        = string
}

variable "policy_name" {
  description = "Name of the firewall policy"
  type        = string
}

variable "security_profile_group_id" {
  description = "ID of the security profile group to apply in rules"
  type        = string
}

variable "inet_vpc" {
  description = "The target VPC network (self-link or name) to attach the policy"
  type        = string
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
    tls_inspect            = optional(bool)
  }))
}