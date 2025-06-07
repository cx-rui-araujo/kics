package main

__rego_metadata__ = {
  "id": "KICS-ABC-123",
  "title": "RUM App Monitor allows untrusted domains in domain_list",
  "description": "Detects aws_rum_app_monitor with domain_list containing wildcard or untrusted domains, which may allow cross-site data collection.",
  "severity": "MEDIUM"
}

denies[message] {
  resource := input.resource_changes[_]
  resource.type == "aws_rum_app_monitor"
  resource.change.after.domain_list[_] == "*"
  message := sprintf("Resource '%s' has an open wildcard in domain_list, which may expose monitoring data to untrusted origins.", [resource.address])
}