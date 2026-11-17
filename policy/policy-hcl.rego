# Place at: policy/policy-hcl.rego
#
# Same guardrails as policy.rego, but written for Terraform SOURCE files (HCL),
# so the pipeline needs no cloud credentials or terraform plan.
#
# Run locally:
#   conftest test terraform/secure --parser hcl2 --policy policy
# If a rule never triggers, inspect the parsed structure with:
#   conftest parse terraform/insecure/main.tf --parser hcl2

package main

import rego.v1

deny contains msg if {
	some name
	fw := input.resource.google_compute_firewall[name]
	fw.source_ranges[_] == "0.0.0.0/0"
	msg := sprintf("google_compute_firewall.%s allows 0.0.0.0/0 (CIS GCP 3.6)", [name])
}

deny contains msg if {
	some name
	m := input.resource.google_storage_bucket_iam_member[name]
	m.member in {"allUsers", "allAuthenticatedUsers"}
	msg := sprintf("google_storage_bucket_iam_member.%s grants public access (OWASP A01)", [name])
}

deny contains msg if {
	some name
	input.resource.google_service_account_key[name]
	msg := sprintf("google_service_account_key.%s: keys are forbidden, use Workload Identity", [name])
}

deny contains msg if {
	some name
	m := input.resource.google_project_iam_member[name]
	m.role in {"roles/owner", "roles/editor"}
	msg := sprintf("google_project_iam_member.%s uses basic role %s", [name, m.role])
}

deny contains msg if {
	some name
	b := input.resource.google_storage_bucket[name]
	not b.public_access_prevention == "enforced"
	msg := sprintf("google_storage_bucket.%s must set public_access_prevention = \"enforced\"", [name])
}
