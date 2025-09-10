package main

import data.kics.tfconfig as tfconfig

__rego_metadata__ = {
  "id": "TF_AWS_APPFLOW_FLOW_001",
  "title": "Insecure Salesforce Bulk API usage in AppFlow",
  "severity": "HIGH",
  "type": "VULNERABILITY",
  "resource_type": "aws_appflow_flow"
}

deny[issue] {
  resource := tfconfig.get_resource(input, "aws_appflow_flow", id)
  api := resource.config.destination_flow_config[0].destination_connector_properties[0].salesforce[0].data_transfer_api
  api == "BULK"
  issue := {
    "id": id,
    "message": sprintf("AppFlow '%s' uses Salesforce Bulk API which may bypass encryption controls", [id])
  }
}