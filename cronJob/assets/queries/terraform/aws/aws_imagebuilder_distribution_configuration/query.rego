package aws_imagebuilder

__rego_metadata__ := {
    "id": "AWS_IMAGEBUILDER_SSM_PARAMETER_INSECURE",
    "title": "SSM Parameter for AMI ID stored without SecureString and KMS encryption",
    "severity": "MEDIUM",
    "description": "Ensure that ssm_parameter_configuration.type is SecureString and a kms_key_id is specified to encrypt the parameter value.",
    "supported_resources": ["aws_imagebuilder_distribution_configuration"]
}

violation[resource] {
    resource := input.resource[_]
    resource.type == "aws_imagebuilder_distribution_configuration"
    dist_blocks := [db | db := resource.block.blocks[_]; db.type == "distribution"]
    dist_blocks != []
    distribution := dist_blocks[0]
    ssm_blocks := [sb | sb := distribution.block.blocks[_]; sb.type == "ssm_parameter_configuration"]
    ssm_blocks != []
    ssm := ssm_blocks[0]
    attr_type := ssm.block.attributes["type"].value
    kms := ssm.block.attributes["kms_key_id"]
    (attr_type != "SecureString" or not kms)
}