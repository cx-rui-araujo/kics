package main

__rego_metadata__ := {
    "id": "AWS_CWC_001",
    "title": "CloudWatch Event Connection should define a customer-managed KMS key",
    "severity": "MEDIUM",
    "type": "VULNERABILITY",
    "metadata": {
        "protocol": "Terraform",
        "provider": "aws",
        "resource": "aws_cloudwatch_event_connection"
    }
}

violation[conn] {
    conn := input.resource.aws_cloudwatch_event_connection[_]
    not conn.values.kms_key_identifier
}