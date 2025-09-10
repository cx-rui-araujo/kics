package terraform.aws.WorkSpacesDirectory

import data.terraform as tf

__rego_metadata__ := {
  "id": "KICS-1234",        # arbitrary unique ID
  "title": "Insecure WorkSpaces user identity type",
  "severity": "MEDIUM",
  "type": "VULNERABILITY",
  "uri": "terraform-provider-aws/aws/resource_aws_workspaces_directory.go"
}

deny[msg] {
  # Iterate all aws_workspaces_directory resources
  resource_blocks := tf.resource_changes
  rc := resource_blocks[_]
  rc.type == "aws_workspaces_directory"

  # Check if the new configuration uses the insecure SIMPLE_AD identity type
  after := rc.change.after
  after.user_identity_type == "SIMPLE_AD"

  msg := sprintf("Resource '%v' uses insecure user_identity_type 'SIMPLE_AD' in aws_workspaces_directory", [rc.name])
}