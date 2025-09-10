package tfaws

__rego_metadata__ := {"id":"KICS-aws-appflow-data-transfer-api","title":"Detect aws_appflow_flow with data_transfer_api enabled","severity":"HIGH","type":"terraform","metadata":{"category":"Security","technology":"AWS","recommended_action":"Disable data_transfer_api unless required"}}

violation[resource] {
  resource := input.resource[_]
  resource.type == "aws_appflow_flow"
  some i
  dfc := resource.values.destination_flow_config[i]
  some j
  dcp := dfc.destination_connector_properties[j]
  some k
  sf := dcp.salesforce[k]
  sf.data_transfer_api == true
}