package main

__rego_metadata__ := {
    "id": "AWS_IMAGEBUILDER_SSM_ENCRYPTION",
    "title": "Ensure ssm_parameter_configuration in aws_imagebuilder_distribution_configuration is encrypted",
    "severity": "MEDIUM",
    "type": "VULNERABILITY",
}

deny[issue] {
    module := input.modules[_]
    resource := module.resources[_]
    resource.type == "aws_imagebuilder_distribution_configuration"
    distribution := resource.values.distribution[_]
    ssm_conf := distribution.ssm_parameter_configuration[0]
    not ssm_conf.kms_key_id
    issue := {
        "resource_id": resource.address,
        "message": "The ssm_parameter_configuration block must specify a kms_key_id to encrypt the parameter store data",
    }
}