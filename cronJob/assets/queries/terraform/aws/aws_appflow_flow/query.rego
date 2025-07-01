package tfaws

deny[msg] {
  resource := config.resource.aws_appflow_flow[_]
  api := resource.destination_flow_config.destination_connector_properties.salesforce.data_transfer_api
  api != "Rest"
  msg = sprintf("Insecure data_transfer_api '%v' detected, must be 'Rest'", [api])
}