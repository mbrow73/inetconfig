terraform {
  required_providers {
    google = {
      source = "hashicorp/google"
      version = "6.31.0"
    }
  }
}

provider "google" {
  project = "inet-457818"
  credentials = var.credentials
}