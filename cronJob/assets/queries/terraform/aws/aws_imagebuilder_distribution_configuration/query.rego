package tfimagebuilder_ssm

deny[{"msg": msg, "resource": resource.address}] {
  resource := input.resource
  resource.type == "aws_imagebuilder_distribution_configuration"
  distribution := resource.values.distribution[_]
  ssm := distribution.ssm_parameter_configuration
  (not ssm.kms_key_id) or ssm.type != "SECURE_STRING"
  msg := sprintf("SSM parameter %v in AWS Image Builder distribution configuration %v is not securely stored (requires SECURE_STRING and kms_key_id)", [ssm.parameter_name, resource.address])
}