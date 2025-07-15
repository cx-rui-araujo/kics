package aws.msk.bootstrap_iam

__rego_meta__ := {"id": "KICS-AWS-001", "severity": "MEDIUM", "title": "Unrestricted Kafka SASL IAM Bootstrap Brokers", "description": "Detects if an IAM policy grants kafka:GetBootstrapBrokers to all principals, which can expose bootstrap brokers endpoints."}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_policy"
  stmt := resource.change.after.policy.Document.Statement[_]
  stmt.Effect == "Allow"
  stmt.Action[_] == "kafka:GetBootstrapBrokers"
  stmt.Principal.AWS == "*"
}
