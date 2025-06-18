package kics

# Avoid using high-volume bulk API for Salesforce data transfer in AppFlow
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_appflow_flow"
  after := resource.change.after.destination_flow_config.destination_connector_properties.salesforce
  after.data_transfer_api == "BULK_API_2_0"
  msg := sprintf("aws_appflow_flow '%s' uses BULK_API_2_0 for Salesforce data_transfer_api which may lead to excessive data exposure.", [resource.change.after.name])
}