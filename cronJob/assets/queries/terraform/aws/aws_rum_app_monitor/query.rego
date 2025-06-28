package tfsec

__rego_metadata__ := {
  "id": "AWS999",
  "title": "Ensure aws_rum_app_monitor domain_list and domain are properly configured",
  "severity": "MEDIUM"
}

violation[{
  "msg": msg,
  "metadata": __rego_metadata__
}] {
  resource := input.resource_changes[_]
  resource.type == "aws_rum_app_monitor"
  after := resource.change.after

  # Check for missing domain (now optional)
  missing_domain := after.domain == null

  # Check for wildcard entries in domain_list
  wildcard_entry := after.domain_list[_]
  contains(wildcard_entry, "*")

  (missing_domain or wildcard_entry)
  msg := sprintf("aws_rum_app_monitor '%s' misconfiguration: %s",
    [resource.address,
     cond(missing_domain, "domain is not set", "domain_list contains wildcard entry")
    ])
}

# helper for conditional message
cond(true, a, _) = a
cond(false, _, b) = b