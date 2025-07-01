package terraform.aws.ecs

import data.terraform as tf

# Detect non-blocking defaultLogDriverMode which may drop logs unexpectedly
violation[issue] {
  resource := tf.resource.aws_ecs_account_setting_default[_]
  resource.config.name.value == "defaultLogDriverMode"
  resource.config.value.value == "non-blocking"
  issue := sprintf("Resource '%s' uses non-blocking defaultLogDriverMode, which may result in dropped logs", [resource.address])
}