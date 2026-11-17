# ============================================================
# INSECURE BASELINE - deliberately bad, for scanning practice.
# Never apply this to a real project.
# Run: checkov -f insecure.tf
# ============================================================

variable "project_id" {
  type = string
}

provider "google" {
  project = var.project_id
  region  = "us-central1"
}

# ISSUE 1: Public bucket, no versioning, no encryption key, no logging
# OWASP A01 Broken Access Control | CIS GCP 5.1 | ATT&CK T1530 (Data from Cloud Storage)
resource "google_storage_bucket" "data" {
  name     = "${var.project_id}-customer-data"
  location = "US"
}

resource "google_storage_bucket_iam_member" "public" {
  bucket = google_storage_bucket.data.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

# ISSUE 2: SSH open to the whole internet
# CIS GCP 3.6 | ATT&CK T1190 (Exploit Public-Facing Application)
resource "google_compute_firewall" "ssh_open" {
  name    = "allow-ssh-anywhere"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"]
}

# ISSUE 3: Over-privileged service account + long-lived JSON key
# CIS GCP 1.4 / 1.5 | ATT&CK T1078.004 (Valid Accounts: Cloud Accounts)
resource "google_service_account" "app" {
  account_id   = "app-sa"
  display_name = "App service account"
}

resource "google_project_iam_member" "app_editor" {
  project = var.project_id
  role    = "roles/editor"
  member  = "serviceAccount:${google_service_account.app.email}"
}

resource "google_service_account_key" "app_key" {
  service_account_id = google_service_account.app.name
}
