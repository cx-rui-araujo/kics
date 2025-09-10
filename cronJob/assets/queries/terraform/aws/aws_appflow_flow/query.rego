package tfplan.rule

import data.tfplan

__rego_metadata__ := {
  "id": "AWS_APPFLOW_001",
  "title": "Avoid using public data transfer API for Salesforce connector",
  "severity": "HIGH",
  "type": "VIOLATION"
}

denied[response] {
  resource := tfplan.resource_changes[_]
  resource.type == "aws_appflow_flow"
  after := resource.change.after
  after.destination_flow_config.destination_connector_properties.salesforce.data_transfer_api == "Public"
  response := {
    "resource": resource.address,
    "message": sprintf("Resource '%s' uses public data transfer API, which may expose data to the internet.", [resource.address])
  }
}