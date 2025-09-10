package kics

# Detect aws_rum_app_monitor with wildcard or missing domains
violation[{{"msg": msg}}] {
  resource := input.resource_changes[_]
  resource.type == "aws_rum_app_monitor"
  after := resource.change.after
  # imaginary vulnerability: wildcard domain_list or missing single domain allows open access
  (count([d | d := after.domain_list[_]; contains(d, "*") ]) > 0) || (after.domain_list == null)
  msg := sprintf("aws_rum_app_monitor '%s' has unsafe domain_list configuration: '%v'", [resource.address, after.domain_list])
}