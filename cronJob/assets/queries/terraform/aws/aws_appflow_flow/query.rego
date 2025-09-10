package terraform.aws.appflow_flow

import data.kics as kics

violation[resource] {
  resource_change := input.resource_changes[_]
  resource_change.type == "aws_appflow_flow"
  api := resource_change.change.after.destination_flow_config.destination_connector_properties.salesforce.data_transfer_api
  api == "SOAP"
  resource := resource_change.address
  kics.violation({"resource": resource, "message": "Using SOAP API for Salesforce data transfer may expose credentials in request headers."})
}