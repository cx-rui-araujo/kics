package terraform.security.aws

__rego_metadata__ := {
  "id": "AWS_KAFKA_GETBOOTSTRAPBROKERS_RESTRICT",
  "title": "Ensure IAM policies do not allow kafka:GetBootstrapBrokers on all resources",
  "severity": "HIGH",
  "type": "VULNERABILITY"
}

deny[msg] {
  resource := input.resource[_]
  resource.type == "aws_iam_policy"  
  stmt := resource.values.policy[0].statement[_]
  stmt.effect == "Allow"
  action := stmt.action[_]
  action == "kafka:GetBootstrapBrokers"
  res := stmt.resource[_]
  res == "*"
  msg := sprintf("IAM policy '%s' allows kafka:GetBootstrapBrokers on all resources. Restrict the resource field.", [resource.name])
}