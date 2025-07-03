package main

violation[{"resource": resource.address, "msg": msg}] {
  resource := input.resource_changes[_]
  resource.type == "aws_appflow_flow"
  after := resource.change.after
  after.destination_flow_config.destination_connector_properties.salesforce.data_transfer_api == true
  msg := "aws_appflow_flow should not have data_transfer_api enabled; enabling may cause data leakage."
}