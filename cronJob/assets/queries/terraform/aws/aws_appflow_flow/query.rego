package aws.appflow

import data.terraform as tf

# KICS rule to detect insecure Salesforce data_transfer_api usage
# (Using BULK can lead to API overload & potential data leakage)

deny[message] {
  resource := tf.plan.resource_changes[_]
  resource.Type == "aws_appflow_flow"
  config := resource.change.after.destination_flow_config.destination_connector_properties.salesforce
  config.data_transfer_api == "BULK"
  message := sprintf("Resource '%s' uses BULK Data Transfer API, which may be insecure", [resource.address])
}