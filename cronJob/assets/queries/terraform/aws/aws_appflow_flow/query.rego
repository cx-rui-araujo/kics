package terraform.aws.appflow

__rego_metadata__ := {
  "id": "KICS_AWS_APPFLOW_SF_DATATRANSFERAPI",
  "title": "Ensure secure Salesforce Data Transfer API in AWS AppFlow",
  "severity": "MEDIUM",
  "type": "MISCONFIGURATION",
  "category": "security"
}

violation[resource] {
  resource := input.resource_config.aws_appflow_flow[_]
  api := resource.destination_flow_config[0].destination_connector_properties[0].salesforce[0].data_transfer_api
  api == "BASIC_TRANSFER"
}
