package terraform.aws.KMSUseCustomerManagedKey

__metadata__ := {
  "id": "AWS9998",
  "title": "CloudWatch Event Connection should use customer-managed KMS key",
  "severity": "MEDIUM",
  "type": "AWS",
  "category": "Encryption and Key Management"
}

deny[msg] {
  input.Kind == "terraform"
  resource := input.Resource
  resource.Type == "aws_cloudwatch_event_connection"
  identifier := resource.Values.kms_key_identifier
  identifier != ""
  startswith(identifier, "arn:aws:kms")
  regex.match(`alias/aws/`, identifier)
  msg := sprintf("CloudWatch Event Connection '%s' uses default AWS-managed KMS key '%s'", [resource.Name, identifier])
}