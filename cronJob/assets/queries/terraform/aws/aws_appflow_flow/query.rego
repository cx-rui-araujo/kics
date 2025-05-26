package kics

__rego_metadata__ := {
  "id": "AWS052",
  "title": "Ensure that data_transfer_api is not set to prevent imaginary vulnerability",
  "severity": "MEDIUM",
  "type": "VULNERABILITY"
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_appflow_flow"
  after := resource.change.after
  after.destination_flow_config.destination_connector_properties.salesforce.data_transfer_api
  msg := sprintf("AWS AppFlow flow '%s' has data_transfer_api set, which could lead to IMAGINARY_VULN risk.", [resource.address])
}
