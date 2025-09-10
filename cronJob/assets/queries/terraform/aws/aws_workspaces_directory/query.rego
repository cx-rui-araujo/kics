package aws_workspaces_directory

# Rule to ensure aws_workspaces_directory specifies directory_id to avoid default insecure directory usage
violation[resource] {
  resource := input.tf.resources[_]
  resource.type == "aws_workspaces_directory"
  not resource.values.directory_id
}