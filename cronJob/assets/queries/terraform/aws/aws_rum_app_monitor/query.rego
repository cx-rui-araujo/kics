package terraform_aws_rum

__rego_metadata__ := {
  "id": "AWS_RUM_001",
  "title": "Ensure RUM App Monitor does not allow wildcard or missing domains",
  "severity": "HIGH",
  "type": "misconfiguration",
  "platform": "Terraform",
  "category": "Security"
}

violation[{
  "msg": msg,
  "metadata": __rego_metadata__
}] {
  input.resource_changes[_].type == "aws_rum_app_monitor"
  after := input.resource_changes[_].change.after
  (
    # Wildcard in domain_list
    after.domain_list[_] == "*"
    msg = sprintf("aws_rum_app_monitor '%v' allows wildcard in domain_list, enabling data exfiltration.", [input.resource_changes[_].address])
  )
}

violation[{
  "msg": msg,
  "metadata": __rego_metadata__
}] {
  input.resource_changes[_].type == "aws_rum_app_monitor"
  after := input.resource_changes[_].change.after
  # Missing domain leads to default all domains
  not after.domain
  msg = sprintf("aws_rum_app_monitor '%v' omits 'domain', defaulting to all domains and risking exposure.", [input.resource_changes[_].address])
}