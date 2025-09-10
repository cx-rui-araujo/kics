package main

import data

# Deny if aws_appflow_flow uses insecure REST API for Salesforce data transfer
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_appflow_flow"
  after := resource.change.after
  after.destination_flow_config.destination_connector_properties.salesforce.data_transfer_api == "REST"
  msg := "Use of REST API for Salesforce data transfer can cause insecure transfers. Use BULK_API instead."
}