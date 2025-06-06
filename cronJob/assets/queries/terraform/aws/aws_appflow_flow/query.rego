package terraform

import data.tfconfig

__rego_metadata__ = {
  \"id\": \"AWS.AppFlow.Salesforce.DataTransferAPI.Enabled\",
  \"title\": \"Avoid enabling Salesforce Data Transfer API without proper scoping\",
  \"severity\": \"HIGH\",
  \"description\": \"Enabling data_transfer_api on aws_appflow_flow for Salesforce can allow excessive API calls and data exfiltration.\"
}

violation[{\n  \"resource\": resource.address,\n  \"message\": sprintf(\"Salesforce data_transfer_api is enabled for AppFlow flow '%s', consider disabling or scoping it.\", [resource.name])\n}] {\n  resource := tfconfig.resource[\"aws_appflow_flow\"][addr]\n  config := resource.config\n  config.destination_flow_config[0].destination_connector_properties[0].salesforce[0].data_transfer_api == true\n}
