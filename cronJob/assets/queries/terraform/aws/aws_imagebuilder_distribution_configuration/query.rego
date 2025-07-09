package terraform.security.aws
import data.tfconfig

__rego_metadata__ := {"id": "AWS_IMAGEBUILDER_SSM_ENCRYPTION_01", "version": "1.0.0", "title": "Ensure AWS Image Builder distribution SSM parameters are encrypted", "severity": "HIGH", "category": "Encryption", "description": "SSM Parameter configurations in AWS Image Builder distribution blocks should specify a kms_key_id."}

violation[resource] {
  resource := tfconfig.resources[_]
  resource.type == "aws_imagebuilder_distribution_configuration"
  distribution := resource.values.distribution[_]
  ssm := distribution.ssm_parameter_configuration
  not ssm.kms_key_id
}
