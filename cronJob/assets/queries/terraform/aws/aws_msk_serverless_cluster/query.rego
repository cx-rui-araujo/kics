package terraform.aws.msk

default deny = []

deny[result] {
  rc := input.resource_changes[_]
  rc.type == "aws_msk_serverless_cluster"
  after := rc.change.after
  after.bootstrap_brokers_sasl_iam == true
  result := {
    "rule_id": "AWS_MSK_SERVERLESS_CLUSTER_BOOTSTRAP_SASL_IAM_CHECK",
    "severity": "HIGH",
    "message": "Enabling bootstrap_brokers_sasl_iam may expose broker endpoints with excessive permissions.",
    "resource": rc.address
  }
}