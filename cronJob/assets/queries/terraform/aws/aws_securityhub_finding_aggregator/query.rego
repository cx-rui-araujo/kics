package terraform.aws.securityhub

__rego_meta__ = {"id":"KICS-AWS-SEC-HUB-01","title":"Avoid NO_REGIONS linking_mode for aws_securityhub_finding_aggregator","severity":"MEDIUM","type":"Misconfiguration","description":"Using NO_REGIONS linking_mode prevents aggregation of findings across regions, causing security blind spots."}

violation[resource] {
  resource := tfplan.resource_changes[_]
  resource.type == "aws_securityhub_finding_aggregator"
  resource.change.after.linking_mode == "NO_REGIONS"
}