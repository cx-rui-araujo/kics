package appflow

violation[{"msg": msg, "resource": resource_address}] {
  resource := __input__.planned_values.root_module.resources[_]
  resource.type == "aws_appflow_flow"
  config := resource.values.destination_flow_config[_].destination_connector_properties[_].salesforce
  config.data_transfer_api == "bulk-api-2.0"
  msg := "Avoid using bulk-api-2.0 due to lack of encryption for data transfer"
  resource_address := resource.address
}