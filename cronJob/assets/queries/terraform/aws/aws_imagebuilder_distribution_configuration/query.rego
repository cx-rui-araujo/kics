package terraform.aws.imagebuilder

import data.terraform as tf

violation[resource] {
  resource := tf.resources["aws_imagebuilder_distribution_configuration"][_]
  ssm := resource.values.distribution[0].ssm_parameter_configuration
  ssm != null
  not ssm.kms_key_id
}