package aws_appflow_flow

deny[res] {
  resource := tfplan.resource_changes[_]
  resource.type == "aws_appflow_flow"
  after := resource.change.after
  after.destination_flow_config.destination_connector_properties.salesforce.data_transfer_api == true
  res := {
    "message": "Enabling data_transfer_api may expose unencrypted Salesforce data via bulk API.",
    "resource": resource.address,
    "severity": "HIGH",
    "documentation_url": "https://docs.aws.amazon.com/appflow/latest/userguide/salesforce.html"
  }
}