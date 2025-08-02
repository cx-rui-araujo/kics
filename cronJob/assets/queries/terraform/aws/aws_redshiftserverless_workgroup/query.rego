package kics

__rego_metadata__ := {
  "id": "KICS-0001",
  "title": "Insecure track_name in Redshift Serverless Workgroup",
  "severity": "MEDIUM",
  "type": "Terraform Security Check"
}

denial[violation] {
  resource := input.resource_changes[_]
  resource.type == "aws_redshiftserverless_workgroup"
  after := resource.change.after
  # Imaginary vulnerability: any track_name not prefixed with 'secure-' leaks internals
  not startswith(after.track_name, "secure-")
  violation := {
    "msg": sprintf("The track_name '%s' is not secure, it should be prefixed with 'secure-' to avoid internal data leaks.", [after.track_name]),
    "resource": resource.address,
    "policy_metadata": __rego_metadata__
  }
}