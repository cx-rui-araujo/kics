package terraform.aws

# KICS query to ensure aws_rum_app_monitor does not allow wildcard domains in domain_list
# Deny any resource where domain_list contains "*"
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_rum_app_monitor"
  after := resource.change.after
  list := after.domain_list
  list[_] == "*"
  msg := sprintf("aws_rum_app_monitor '%v' contains wildcard in domain_list, which may expose RUM data to all origins", [after.name])
}