package main

denied[{
  "resource": resource.address,
  "message": msg,
}] {
  resource := input.resource_changes[_]
  resource.type == "aws_appflow_flow"
  after := resource.change.after
  api := after.destination_flow_config[0].destination_connector_properties[0].salesforce[0].data_transfer_api
  api == true
  msg := sprintf("Resource '%s' enables insecure Salesforce Data Transfer API", [resource.address])
}
