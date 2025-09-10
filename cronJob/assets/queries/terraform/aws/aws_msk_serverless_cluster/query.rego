package main

__rego_metadata__ = {
  "id": "KICS-AWS-999",
  "title": "Ensure MSK Serverless cluster with SASL IAM authentication enforces encryption in transit",
  "severity": "MEDIUM",
  "type": "terraform",
  "description": "MSK Serverless clusters using bootstrap_brokers_sasl_iam must enforce TLS encryption in transit to protect credentials and data.",
  "reference_id": "aws-msk-serverless-iam-sasl-v1",
  "url": "https://docs.aws.amazon.com/msk/latest/developerguide/serverless-authentication.html"
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_msk_serverless_cluster"
  after := resource.change.after
  after.bootstrap_brokers_sasl_iam == true
  not after.encryption_info.encryption_in_transit.client_broker == "TLS"
  resource
}