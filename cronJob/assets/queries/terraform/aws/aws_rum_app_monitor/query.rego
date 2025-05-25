package terraform.aws_rum_app_monitor

# In KICS, this rule detects aws_rum_app_monitor resources
# that specify a wildcard in domain_list, which may
# unintentionally expose monitoring to all subdomains.
violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_rum_app_monitor"
  after := resource.change.after
  after.domain_list != null
  domain := after.domain_list[_]
  contains_wildcard(domain)
}

# helper to check for wildcard usage
contains_wildcard(domain) {
  endswith(domain, "*")
}