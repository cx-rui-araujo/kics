package terraform.aws

# Deny any aws_rum_app_monitor with a domain_list containing wildcard entries
# or potentially unsafe domains that could lead to data exfiltration

deny[msg] {
  resource := tfplan.resource_changes[_]
  resource.type == "aws_rum_app_monitor"
  after := resource.change.after
  domain := after.domain_list[_]
  contains(domain, "*")
  msg := sprintf("Resource %s has unsafe wildcard domain in domain_list: %s", [resource.address, domain])
}