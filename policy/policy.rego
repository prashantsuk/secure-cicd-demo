# OPA / Conftest policy-as-code for Terraform plans.
#
# Usage:
#   terraform plan -out=tfplan
#   terraform show -json tfplan > tfplan.json
#   conftest test tfplan.json --policy .
#
# Each rule blocks an insecure change BEFORE it reaches production.

package main

import rego.v1

# Rule 1: no firewall open to the whole internet
deny contains msg if {
	rc := input.resource_changes[_]
	rc.type == "google_compute_firewall"
	rc.change.after.source_ranges[_] == "0.0.0.0/0"
	msg := sprintf("%s: firewall allows 0.0.0.0/0 (CIS GCP 3.6)", [rc.address])
}

# Rule 2: no public IAM members on any resource
deny contains msg if {
	rc := input.resource_changes[_]
	startswith(rc.type, "google_storage_bucket_iam")
	rc.change.after.member in {"allUsers", "allAuthenticatedUsers"}
	msg := sprintf("%s: grants access to %s (OWASP A01)", [rc.address, rc.change.after.member])
}

# Rule 3: no long-lived service account keys
deny contains msg if {
	rc := input.resource_changes[_]
	rc.type == "google_service_account_key"
	msg := sprintf("%s: service account keys are forbidden, use Workload Identity", [rc.address])
}

# Rule 4: no basic roles (owner/editor) at project level
deny contains msg if {
	rc := input.resource_changes[_]
	rc.type == "google_project_iam_member"
	rc.change.after.role in {"roles/owner", "roles/editor"}
	msg := sprintf("%s: basic role %s violates least privilege", [rc.address, rc.change.after.role])
}

# Rule 5: buckets must enforce public access prevention
deny contains msg if {
	rc := input.resource_changes[_]
	rc.type == "google_storage_bucket"
	rc.change.after.public_access_prevention != "enforced"
	msg := sprintf("%s: public_access_prevention must be 'enforced'", [rc.address])
}
