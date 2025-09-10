package tfawsimgbuild
import data.tfconfig as tfconfig

violation[message] {
  resource := tfconfig.resource["aws_imagebuilder_distribution_configuration"][name]
  distribution := resource.values.distribution[_]
  ssm := distribution.ssm_parameter_configuration
  not ssm.kms_key_id
  message := sprintf("Resource '%s' uses ssm_parameter_configuration without encryption (kms_key_id missing)", [name])
}