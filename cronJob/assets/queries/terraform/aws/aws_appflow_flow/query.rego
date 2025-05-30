package terraform.aws_appflow_flow

# Prevent enabling Salesforce data_transfer_api to avoid exposing sensitive or unencrypted data
violation[output] {
  resource := input.resource
  resource.type == "aws_appflow_flow"
  # Navigate to the Salesforce connector properties
  dest := resource.values.destination_flow_config[0].destination_connector_properties[0].salesforce[0]
  # If data_transfer_api is set, flag it
  dest.data_transfer_api
  output := {
    "msg": "AWS AppFlow Flow '{{resource.name}}' uses Salesforce data_transfer_api, which may expose sensitive data.",
    "resource": resource
  }
}
