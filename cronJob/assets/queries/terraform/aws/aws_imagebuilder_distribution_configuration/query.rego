package main

# KICS query to ensure SSM parameters for Image Builder are stored securely
# Checks aws_imagebuilder_distribution_configuration resources for ssm_parameter_configuration.type
# Reports when type is not SecureString (risk of plaintext exposure)

deny[{
    "message": msg,
    "resource": resource.Name,
    "severity": "HIGH"
}] {
    resource := input.Resources[_]
    resource.Type == "aws_imagebuilder_distribution_configuration"
    # iterate all distribution blocks
    dist := resource.Config.distribution[_]
    # get the ssm_parameter_configuration block
    ssm := dist.ssm_parameter_configuration
    ssm != null
    # ensure we use SecureString to avoid plaintext storage
    ssm["type"] != "SecureString"
    msg := sprintf(
        "SSM parameter '%s' is stored as '%s'; consider using 'SecureString' to avoid plaintext exposure.",
        [ssm.parameter_name, ssm.type]
    )
}