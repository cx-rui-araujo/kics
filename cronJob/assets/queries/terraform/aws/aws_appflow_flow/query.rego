package aws_appflow_flow

__rego_metadata__ := {
  "id": "AWS012",
  "title": "Prohibit unsafe Salesforce data_transfer_api settings",
  "severity": "MEDIUM",
  "description": "Using BULK_API_2.0 for data_transfer_api may bypass validation and overwhelm target systems."  
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_appflow_flow"
  after := resource.change.after
  api := after.destination_flow_config.destination_connector_properties.salesforce.data_transfer_api
  api == "BULK_API_2.0"
  msg := sprintf("Resource '%v' uses insecure data_transfer_api BULK_API_2.0, switch to REST_API for safe behavior", [resource.address])
}