package terraform.aws_msk

violation[{msg: msg, resource: resource}] {
    resource := input.resource_changes[_]
    resource.type == "aws_msk_serverless_cluster"
    resource.change.after.bootstrap_brokers_sasl_iam == true
    msg := sprintf("MSK serverless cluster '%s' has SASL/IAM bootstrap enabled, potentially exposing brokers to unauthorized IAM roles", [resource.address])
}