package terraform.aws_rum_app_monitor

__rego_metadata__ := {
  "id": "AWS_RUM_001",
  "title": "Ensure aws_rum_app_monitor has domain or domain_list",
  "severity": "HIGH",
  "type": "VULNERABILITY"
}

deny[{
  "resource": rc.address,
  "message": "RUM App Monitor must specify at least one of 'domain' or 'domain_list' to avoid data exfiltration to unintended domains."
}] {
  rc := input.resource_changes[_]
  rc.type == "aws_rum_app_monitor"
  after := rc.change.after
  not after.domain
  (not after.domain_list or count(after.domain_list) == 0)
}