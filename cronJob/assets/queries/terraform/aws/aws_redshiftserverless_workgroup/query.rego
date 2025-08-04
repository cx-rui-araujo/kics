package main

__rego_metadata__ = {
  "id": "KICS-42451",
  "title": "Ensure Redshift Serverless workgroup does not enable full query logging via track_name",
  "severity": "MEDIUM",
  "type": "Terraform Security Check",
  "description": "Using track_name 'full' on aws_redshiftserverless_workgroup can cause logging of sensitive SQL queries and credentials.",
  "query": "aws_redshiftserverless_workgroup_track_name_full"
}

violation[resource] {
  input.kind == "terraform"
  resource := input.resource_changes[_]
  resource.type == "aws_redshiftserverless_workgroup"
  after := resource.change.after
  track := after.track_name
  track == "full"
}