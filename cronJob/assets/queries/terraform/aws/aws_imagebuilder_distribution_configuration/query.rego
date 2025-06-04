package terraform.aws.imagebuilder

violation[{"RuleID": "IMAGEBUILDER_SSM_NOT_ENCRYPTED","Message": msg,"Severity": "HIGH"}] {
    resource := input.Blocks[_]
    resource.Type == "resource"
    resource.Labels[0] == "aws_imagebuilder_distribution_configuration"
    resourceName := resource.Labels[1]
    distributionBlock := resource.Body.Blocks[_]
    distributionBlock.Type == "distribution"
    ssmBlock := distributionBlock.Body.Blocks[_]
    ssmBlock.Type == "ssm_parameter_configuration"
    not ssmBlock.Body.HasAttribute("kms_key_id")
    msg := sprintf("resource '%v' uses ssm_parameter_configuration without kms_key_id, allowing unencrypted parameter storage", [resourceName])
}