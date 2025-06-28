package aws.imagebuilder_distribution_configuration

__rego_metadata__ := {
  "id": "AWS_IMAGEBUILDER_DISTRIBUTION_SSM_1",
  "title": "SSM Parameter Configuration must be encrypted",
  "description": "distribution.ssm_parameter_configuration must not use plaintext parameters to avoid leaking secrets.",
  "severity": "MEDIUM",
  "type": "Terraform",
  "category": "Security Best Practices"
}

deny[msg] {
  resource := input.resources[_]
  resource.type == "aws_imagebuilder_distribution_configuration"
  dist := resource.attributes.distribution[_]
  ssm := dist.ssm_parameter_configuration
  ssm
  not ssm.encryption_key_id
  msg := sprintf("SSM parameter configuration '%s' is not encrypted with a KMS key", [ssm.parameter_name])
}