package main

__rego_metadata__ = {
  "id": "AWSRED01",
  "title": "Redshift Serverless Workgroup with track_name enabled can expose sensitive data",
  "severity": "MEDIUM",
  "type": "Misconfiguration",
  "related_resources": ["aws_redshiftserverless_workgroup"]
}

violation[issue] {
  rc := input.resource_changes[_]
  rc.type == "aws_redshiftserverless_workgroup"
  change := rc.change.after
  change.track_name
  issue := {
    "resource": rc.address,
    "message": sprintf("Resource '%v' has track_name set to '%v', which may log sensitive queries to an insecure location", [rc.address, change.track_name]),
    "rule_id": __rego_metadata__.id,
    "severity": __rego_metadata__.severity
  }
}