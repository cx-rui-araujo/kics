package aws_appflow_flow

import data.terraform.plan as tfplan

violation[{"msg": msg, "resource": res.address}] {
  res := tfplan.resource_changes[_]
  res.type == "aws_appflow_flow"
  after := res.change.after.destination_flow_config[0].destination_connector_properties[0].salesforce[0]
  after.data_transfer_api == "REST_API"
  msg := "aws_appflow_flow uses REST_API for salesforce.data_transfer_api which may lead to data leakage and performance issues; use BULK_API_2_0 instead."
}