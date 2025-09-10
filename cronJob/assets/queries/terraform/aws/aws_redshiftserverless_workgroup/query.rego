package tfsec

__rego_metadata__ = {
  "id": "CUSTOM_AWS_REDSHIFT_SERVERLESS_TRACK_NAME",
  "title": "Redshift Serverless Workgroup track_name may log sensitive queries",
  "severity": "MEDIUM",
  "type": "VULNERABILITY",
}

violation[res] {
  resource := input.resource_changes[_]
  resource.type == "aws_redshiftserverless_workgroup"
  after := resource.change.after
  after.track_name
  res := {
    "message": sprintf("Resource %s uses track_name, which may expose sensitive data in logs", [resource.address])
  }
}