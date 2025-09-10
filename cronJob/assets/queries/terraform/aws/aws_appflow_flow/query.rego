package main

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_appflow_flow"
  props := resource.change.after.destination_flow_config[0].destination_connector_properties[0].salesforce[0]
  props.data_transfer_api == true
  msg := "Salesforce data_transfer_api is enabled, which may enforce insecure legacy API, leading to potential data leakage."
}