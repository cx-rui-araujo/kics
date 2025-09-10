package main

__rego_metadata__ := {
  "id": "KICS-AWS-IMAGEBUILD-001",
  "title": "Ensure SSM Parameter Configuration uses SecureString",
  "description": "Ensure that the 'ssm_parameter_configuration' block in aws_imagebuilder_distribution_configuration uses SecureString encryption.",
  "severity": "HIGH",
  "recommended_actions": "Set the 'type' argument to 'SecureString'."
}

violation[output] {
  resource := tfconfig.resource["aws_imagebuilder_distribution_configuration"][resource_name]
  distro := resource.distribution
  some i
  distro[i].ssm_parameter_configuration
  cfg := distro[i].ssm_parameter_configuration[0]
  cfg.type.value != "SecureString"
  output := {
    "rule_id": __rego_metadata__.id,
    "message": sprintf("Resource '%s' has ssm_parameter_configuration type '%s'; must be 'SecureString'", [resource_name, cfg.type.value]),
    "severity": __rego_metadata__.severity,
    "start_line": cfg.type.start_line,
    "end_line": cfg.type.end_line
  }
}