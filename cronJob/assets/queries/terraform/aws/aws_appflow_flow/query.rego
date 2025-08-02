package terraform.aws.AppflowFlow

# Detect risky Salesforce API usage in aws_appflow_flow
violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_appflow_flow"
  after := resource.change.after.destination_flow_config[0].destination_connector_properties.salesforce
  after.data_transfer_api == "REST_API"
}
