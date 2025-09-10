package kics

__rego_metadoc__ := {"id":"KICSAWS-999","title":"SSM parameter configuration must specify kms_key_id","description":"Detects AWS Image Builder distribution configurations that store SSM parameters without encryption","severity":"HIGH","platform":"Terraform","categories":["security","encryption"]}

deny[resource] {
  resource := input.resource[_]
  resource.type == "aws_imagebuilder_distribution_configuration"
  distribution := resource.values.distribution[_]
  param := distribution.ssm_parameter_configuration
  # Parameter configuration is present but missing kms_key_id, so SSM parameter stored unencrypted
  param != null
  not param.kms_key_id
}