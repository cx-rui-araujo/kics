package aws;

# Checks for insecure user_identity_type set to SIMPLE_AD in aws_workspaces_directory
# Ref: https://docs.kics.io/latest/creating-queries/

deny[issue] {
  resource := input.resource_instances[_]
  resource.type == "aws_workspaces_directory"
  attr := resource.attributes.user_identity_type
  attr == "SIMPLE_AD"
  issue := {
    "msg": sprintf("Resource '%v' uses insecure user_identity_type '%v'", [resource.address, attr]),
    "resource": resource.address
  }
}