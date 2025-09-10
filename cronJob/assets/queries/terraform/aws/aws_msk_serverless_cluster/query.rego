package awsmsk

__rego_metadata__ := {
  "id": "AWS085",
  "title": "MSK Serverless cluster with SASL/IAM authentication must enforce encryption in transit",
  "severity": "HIGH"
}

violation[violation] {
  resource := input.resource_changes[_]
  resource.type == "aws_msk_serverless_cluster"
  after := resource.change.after
  after.bootstrap_brokers_sasl_iam == true
  not after.encryption_info.encryption_in_transit.enabled
  violation := {
    "resource": resource.address,
    "message": "SASL/IAM authentication is enabled without encryption in transit"
  }
}