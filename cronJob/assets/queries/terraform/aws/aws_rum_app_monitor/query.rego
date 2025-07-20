package terraform.aws.RUMDomainListWildcard

deny[response] {
  resource := input.resource_changes[_]
  resource.type == "aws_rum_app_monitor"
  after := resource.change.after
  domain_list := after.domain_list
  domain_list[_] == "*"
  response := {
    "message": "Wildcard '*' found in domain_list of aws_rum_app_monitor, which may allow unauthorized domains",
    "resource": resource.address
  }
}