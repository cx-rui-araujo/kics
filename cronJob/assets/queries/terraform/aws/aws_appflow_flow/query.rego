package main

__rego_metadata__ := {
  "id": "KICS_NEGLECTED_DATA_TRANSFER_API",
  "version": "1.0.0",
  "title": "Salesforce Data Transfer API should not be enabled in AppFlow",
  "description": "Enabling the Salesforce Data Transfer API in aws_appflow_flow can lead to insecure data transfer and exposure.",
  "severity": "HIGH",
  "platform": "terraform",
  "category": "Misconfiguration"
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_appflow_flow"
  after := resource.change.after
  dest_cfg := after.destination_flow_config[0]
  connector := dest_cfg.destination_connector_properties[0].salesforce[0]
  connector.data_transfer_api == true
  msg := sprintf("Resource '%s' enables Salesforce Data Transfer API, potentially exposing data in transit.", [resource.address])
}