package main

__rego_metadata__ := {
    "id": "KICS-AWS-KE-0001",
    "title": "AWS MSK Serverless bootstrap_brokers_sasl_iam Misconfiguration",
    "severity": "MEDIUM",
    "type": "Misconfiguration"
}

deny[msg] {
    input.kind == "terraform"
    resource := input.resource[_]
    resource.type == "aws_msk_serverless_cluster"
    resource.values.bootstrap_brokers_sasl_iam == true
    msg := sprintf("Resource '%s' has bootstrap_brokers_sasl_iam enabled. Ensure IAM policies restrict kafka:GetBootstrapBrokers to authorized principals.", [resource.name])
}