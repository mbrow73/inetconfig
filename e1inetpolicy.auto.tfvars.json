# INET FIREWALL POLICY #
module "firewall_policy" {
  policy_name               = "inet-policy"
  project_id                = var.project_id
  source                    = "./modules/inet_firewall_policy_e1"
  security_profile_group_id = module.security_profiles.profile_group_id
  vpc_network_id            = var.vpc_network_id

  firewall_rules = [
################################ INGRESS INET INSPECTION RULE #################################
    {
      name                   = "Inspect-known-https"
      description            = "inspect known HTTPS"
      priority               = 1
      direction              = "INGRESS"
      action                 = "apply_security_profile_group"
      security_profile_group = "organizations/2345678432/locations/global/securityProfileGroups/example-security-profile-group"
      enable_logging         = true
      src_ip_ranges          = ["0.0.0.0/0"]
      dest_ip_ranges         = ["0.0.0.0/0"]
      protocol               = "TCP"
      ports                  = ["443"]
      tls_inspection         = true
    }
  ]
}
################################################################################################
