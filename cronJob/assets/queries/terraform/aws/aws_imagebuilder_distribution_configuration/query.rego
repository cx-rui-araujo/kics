package tf.aws.imagebuilder

__rego_metadata__ := {
  "id": "AWS1234",
  "title": "SSM Parameter Configuration must use SecureString",
  "severity": "LOW",
  "type": "VIOLATION"
}

deny[resource] {
  resource := input.resource[_]
  resource.type == "aws_imagebuilder_distribution_configuration"
  distro := resource.config.distribution[_]
  ssm := distro.ssm_parameter_configuration[_]
  not ssm.type == "SecureString"
}