package terraform.security.aws

__rego_metadoc__:
  id: "KICS_AWS_SSM_ENCRYPTION_MISSING"
  title: "Ensure SSM parameter configuration is encrypted"
  severity: "HIGH"
  categories: ["encryption","ssm","aws"]
  scope: ["terraform"]

deny[response] {
  resource := tfplan.resource_changes[_]
  resource.type == "aws_imagebuilder_distribution_configuration"
  distribution := resource.change.after.distribution[_]
  ssm := distribution.ssm_parameter_configuration
  not ssm.key_id
  response := {
    "resource": resource.address,
    "message": "SSM parameter configuration missing KMS key_id, leading to unencrypted parameter storage"
  }
}