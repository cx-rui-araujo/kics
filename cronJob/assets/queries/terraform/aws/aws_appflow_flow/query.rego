package main

violation[{"msg": msg}] {
  resource := input.resource_changes[_]
  resource.type == "aws_appflow_flow"
  resource.change.actions[_] == "create"
  props := resource.change.after.destination_flow_config[0].destination_connector_properties[0].salesforce[0]
  props.data_transfer_api
  msg := "The Salesforce data_transfer_api is enabled without encryption, which may expose sensitive data."
}