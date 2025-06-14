package kics_aws_controltower

// Ensure AWS Control Tower Control always defines a parameters block to avoid default insecure configuration
violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_controltower_control"
  resource.change.after != null
  not resource.change.after.parameters
}