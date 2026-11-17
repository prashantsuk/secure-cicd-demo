# ============================================================
# SECURE VERSION - each block fixes an issue from insecure.tf
# Run: checkov -f secure.tf   (should have far fewer findings)
# ============================================================

variable "project_id" {
  type = string
}

variable "github_repo" {
  type        = string
  description = "owner/repo allowed to deploy, e.g. myuser/devsecops-demo"
}

variable "admin_cidr_via_iap" {
  type    = list(string)
  default = ["35.235.240.0/20"] # Google IAP TCP forwarding range
}

provider "google" {
  project = var.project_id
  region  = "us-central1"
}

# ---------- Encryption: Cloud KMS (customer-managed key) ----------
resource "google_kms_key_ring" "main" {
  name     = "demo-keyring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "bucket" {
  name            = "bucket-key"
  key_ring        = google_kms_key_ring.main.id
  rotation_period = "7776000s" # 90 days

  lifecycle {
    prevent_destroy = true
  }
}

data "google_project" "this" {}

# Cloud Storage service agent must be allowed to use the key
resource "google_kms_crypto_key_iam_member" "gcs_agent" {
  crypto_key_id = google_kms_crypto_key.bucket.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.this.number}@gs-project-accounts.iam.gserviceaccount.com"
}

# ---------- Fix 1: private, versioned, encrypted, logged bucket ----------
resource "google_storage_bucket" "logs" {
  name                        = "${var.project_id}-access-logs"
  location                    = "US"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
}

resource "google_storage_bucket" "data" {
  name                        = "${var.project_id}-customer-data"
  location                    = "US"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true # helps recover from ransomware / accidental deletion
  }

  encryption {
    default_kms_key_name = google_kms_crypto_key.bucket.id
  }

  logging {
    log_bucket = google_storage_bucket.logs.name
  }

  depends_on = [google_kms_crypto_key_iam_member.gcs_agent]
}

# ---------- Fix 2: SSH only through Identity-Aware Proxy ----------
resource "google_compute_firewall" "ssh_iap_only" {
  name    = "allow-ssh-iap-only"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = var.admin_cidr_via_iap

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# ---------- Fix 3: least-privilege service account, NO key ----------
resource "google_service_account" "app" {
  account_id   = "app-sa"
  display_name = "App service account (least privilege)"
}

# Scoped to the one bucket, read-only, instead of project-wide Editor
resource "google_storage_bucket_iam_member" "app_read" {
  bucket = google_storage_bucket.data.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.app.email}"
}

# ---------- Keyless CI/CD: Workload Identity Federation for GitHub ----------
resource "google_iam_workload_identity_pool" "github" {
  workload_identity_pool_id = "github-pool"
  display_name              = "GitHub Actions"
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-provider"

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
  }

  # Only tokens from YOUR repo are accepted
  attribute_condition = "assertion.repository == \"${var.github_repo}\""

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account" "deployer" {
  account_id   = "github-deployer"
  display_name = "Used by GitHub Actions via WIF"
}

resource "google_service_account_iam_member" "wif_binding" {
  service_account_id = google_service_account.deployer.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository/${var.github_repo}"
}

# ---------- Guardrail: block service account key creation ----------
resource "google_org_policy_policy" "no_sa_keys" {
  name   = "projects/${var.project_id}/policies/iam.disableServiceAccountKeyCreation"
  parent = "projects/${var.project_id}"

  spec {
    rules {
      enforce = "TRUE"
    }
  }
}
