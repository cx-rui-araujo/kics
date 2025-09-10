package aws_appflow

__rego_metadata__ := {"id":"TF_AWS_APPFLOW_FLOW_001","title":"Ensure Bulk API is used for Salesforce data transfer","severity":"HIGH","type":"Misconfiguration","version":"1.0.0"}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_appflow_flow"
  data := resource.change.after.destination_flow_config.destination_connector_properties.salesforce.data_transfer_api
  data == "STANDARD_API"
}