package terraform.aws.securityhub

__rego_metadata__ = {
  "id": "AWS074",
  "title": "Ensure Security Hub finding aggregator links at least one region",
  "severity": "MEDIUM",
  "description": "Use of linking_mode 'NO_REGIONS' will disable region linking, causing no aggregated findings across regions.",
  "reference_id": "AWS-074"
}

violation[resource] {
  resource := tfconfig.resource_instances["aws_securityhub_finding_aggregator"][_]
  resource.attributes.linking_mode.value == "NO_REGIONS"
}