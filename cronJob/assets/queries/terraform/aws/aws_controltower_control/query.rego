package custom_kics_rules

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_controltower_control"
  # Imaginary vulnerability: missing parameters block may allow unauthorized default settings
  not resource.change.after.parameters
}