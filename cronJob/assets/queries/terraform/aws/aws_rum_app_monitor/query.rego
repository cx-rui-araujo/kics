package terraform.analysis

denied[res] {
  resource := input.resource_changes[_]
  resource.type == "aws_rum_app_monitor"
  after := resource.change.after
  (
    not after.domain_list
    || length(after.domain_list) == 0
  )
  res := {
    "rule_id": "AWSRUMDomainListMissing",
    "rule_message": "aws_rum_app_monitor should have a non-empty domain_list to avoid accepting events from arbitrary domains.",
    "resource": resource.address
  }
}