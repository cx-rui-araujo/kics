package rules

import "tfplan" as tf

__rego_metadata__ = {
  "id": "KICS-1234",
  "title": "Avoid wildcard domains in aws_rum_app_monitor domain_list",
  "severity": "MEDIUM",
  "type": "VULNERABILITY",
  "docs_link": "https://docs.kics.io/latest/queries/aws/rum"
}

deny[msg] {
  resource := tf.plan.resource_changes[_]
  resource.type == "aws_rum_app_monitor"
  values := resource.change.after.domain_list
  dom := values[_]
  contains(dom, "*")
  msg := sprintf("Wildcard domain '%s' is not allowed in domain_list", [dom])
}