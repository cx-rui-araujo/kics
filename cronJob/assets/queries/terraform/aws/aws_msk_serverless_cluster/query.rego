package kics

violation[violation] {
  resource := input.resource_changes[_]
  resource.type == "aws_msk_serverless_cluster"
  after := resource.change.after
  after.bootstrap_brokers_sasl_iam == true
  violation := {
    "ResourceName": resource.address,
    "Message": "The 'bootstrap_brokers_sasl_iam' attribute is enabled, which may allow unintended IAM principals to retrieve broker endpoints and connect to the cluster."
  }
}