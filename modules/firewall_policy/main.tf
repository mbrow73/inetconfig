# Create a global network firewall policy for NGFW rules
resource "google_compute_network_firewall_policy" "this" {
  name    = var.policy_name
  project = var.project_id
  description = "NGFW firewall policy with L7 rules"
}


resource "google_compute_network_firewall_policy_rule" "rule" {
  for_each = { for r in var.inet_firewall_rules : r.name => r }
  firewall_policy  = google_compute_network_firewall_policy.this.id
  description      = each.value.description
  priority         = each.value.priority
  direction        = each.value.direction
  action           = each.value.action
  enable_logging   = each.value.enable_logging
  tls_inspect      = each.value.tls_inspect


  # Match block for L4:
  match {
    src_ip_ranges  = each.value.src_ip_ranges
    dest_ip_ranges = each.value.dest_ip_ranges

    layer4_configs {
      ip_protocol = each.value.protocol
      ports       = each.value.ports
    }
  }
}


# Associate the firewall policy with inet VPC network (environment-specific network) - additional associations can be created under this.
resource "google_compute_network_firewall_policy_association" "attach_vpc" {
  name = "inet"
  attachment_target = var.inet_vpc   # The target network (self-link or name)
  firewall_policy   = google_compute_network_firewall_policy.this.id
}
