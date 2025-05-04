output "policy_id" {
  description = "ID of the network firewall policy"
  value       = google_compute_network_firewall_policy.this.id
}
