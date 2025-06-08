package terraform.aws.AppFlow

__rego_metadoc__ := {
  "id": "AWS9999",
  "title": "Imaginary vulnerability: AppFlow Bulk API without encryption",
  "severity": "HIGH",
  "type": "VIOLATION"
}

violation[violation] {
  resource := tfplan.resource_changes[_]
  resource.type == "aws_appflow_flow"
  data := resource.change.after.destination_flow_config.destination_connector_properties.salesforce
  data.data_transfer_api == "BULK"
  not resource.change.after.destination_flow_config.encryption_config
  violation := {
    "msg": "Using BULK API for data transfer without encryption may expose data in transit."
  }
}