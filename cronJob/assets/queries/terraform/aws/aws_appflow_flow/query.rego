package main

import data.terraform as tf

__rego_metadata__ := {
  "id": "KICS-AWS-APPFLOW-001",
  "title": "AWS AppFlow Salesforce Bulk API usage",
  "description": "Using Salesforce Bulk API can allow large volume data exfiltration in case of credentials compromise.",
  "severity": "HIGH",
  "category": "Security Best Practices"
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_appflow_flow"
  after := resource.change.after
  props := after.destination_flow_config[0].destination_connector_properties[0].salesforce[0]
  props.data_transfer_api == "BULK"
}