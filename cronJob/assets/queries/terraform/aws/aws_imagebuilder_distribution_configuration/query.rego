package terraform.aws_imagebuilder_distribution_configuration

__rego_metadata__ = {"id":"CUSTOM_AWS_001","version":"1.0.0","title":"SSM parameter configuration without KMS encryption","description":"Detects Image Builder distribution configurations that specify SSM parameter configuration without a kms_key_id, potentially exposing sensitive data in plaintext.","severity":"HIGH","type":"VULNERABILITY","recommendation":"Specify a valid kms_key_id in ssm_parameter_configuration to encrypt the parameter value."}

deny[msg] {
  resource := input.resource
  resource.type == "aws_imagebuilder_distribution_configuration"
  distribution := resource.values.distribution[_]
  ssm := distribution.ssm_parameter_configuration
  ssm
  not ssm.kms_key_id
  msg := sprintf("Resource '%s' defines ssm_parameter_configuration without kms_key_id", [resource.name])
}
