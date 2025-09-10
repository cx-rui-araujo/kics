package main

violation[resource] {
    resource := input.resource_config.aws_imagebuilder_distribution_configuration[*]
    distribution := resource.distribution[*]
    ssm := distribution.ssm_parameter_configuration
    not ssm.kms_key_id
    violation := {
        "message": sprintf("ImageBuilder distribution '%s' ssm_parameter_configuration missing kms_key_id, may expose unencrypted data", [resource._path]),
        "resource": resource._path
    }
}