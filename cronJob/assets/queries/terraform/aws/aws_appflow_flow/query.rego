package KICS.AWS.AppFlow

import input

__rego_metadata__ := {
  "id": "AWS099",
  "title": "AWS AppFlow Salesforce connector using Bulk API",
  "severity": "MEDIUM",
  "type": "VULNERABILITY"
}

violation[resource] {
  resource := input.resource_instances[_]
  resource.type == "aws_appflow_flow"
  props := resource.values.destination_flow_config[0].destination_connector_properties[0].salesforce[0]
  props.data_transfer_api == "Bulk"
}