package main

import data.terraform as tf

invalid_data_transfer_api[resource] {
  resource := tf.resource.aws_appflow_flow[_]
  prop := resource.values.destination_flow_config[0].destination_connector_properties[0].salesforce[0]
  prop.data_transfer_api == "Bulk"
}