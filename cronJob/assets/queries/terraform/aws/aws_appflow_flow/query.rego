package terraform.aws_appflow_flow

__rego_metadata__ := {
  "id": "AWS_APPFLOW_SALESFORCE_BULK_API",
  "title": "Ensure Salesforce Data Transfer API uses BULK mode",
  "severity": "LOW"
}

violation[response] {
  resource := input.resource_changes[_]
  resource.type == "aws_appflow_flow"
  props := resource.change.after.destination_flow_config.destination_connector_properties.salesforce
  props.data_transfer_api != "BULK"
  response := {
    "message": sprintf("Salesforce flow '%s' uses non-bulk data_transfer_api: '%s'", [resource.address, props.data_transfer_api])
  }
}