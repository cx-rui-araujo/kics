package terraform.aws.imagebuilderdistributionconfiguration

import data.terraform.tfconfig as tfconfig

deny[resource] {
  resource := tfconfig.resources[_]
  resource.type == "aws_imagebuilder_distribution_configuration"
  distribution := resource.config.distribution[_]
  distribution.ssm_parameter_configuration != null
}