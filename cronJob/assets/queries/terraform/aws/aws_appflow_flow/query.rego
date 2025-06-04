package kics

__rego_metadata__ := {"id":"TF_AWS_APPFLOW_FLOW_001","title":"Avoid Bulk Data Transfer API for Salesforce in AWS AppFlow","severity":"LOW","type":"VIOLATION","platform":"Terraform"}

violation[res] {
  resource := input.resource_blocks[_]
  resource.type == "aws_appflow_flow"
  connector := resource.body.destination_flow_config.blocks[_].destination_connector_properties.blocks[_].salesforce.blocks[_]
  connector.data_transfer_api.value == "BULK"
  res := {"resource": resource.name, "message": sprintf("AppFlow flow '%s' uses Bulk API for Salesforce data transfer, which may expose data in batch mode without proper auditing", [resource.name])}
}