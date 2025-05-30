package terraform.aws.RUMMonitorDomainMisconfig

import data.tfconfig

__rego_metadata__ := {
  "id": "AWS1000",
  "title": "RUM App Monitor missing domain when domain_list is configured",
  "severity": "MEDIUM",
  "type": "Terraform"
}

violation[res] {
  resourceID := input.resource.id
  resource := input.resource
  resource.type == "aws_rum_app_monitor"
  resource.mode == "managed"
  count(resource.values.domain_list) > 0
  not resource.values.domain
  res := {
    "ResourceID": resourceID,
    "Message": "RUM App Monitor has 'domain_list' configured but no 'domain' specified, allowing unvalidated monitoring endpoints."
  }
}