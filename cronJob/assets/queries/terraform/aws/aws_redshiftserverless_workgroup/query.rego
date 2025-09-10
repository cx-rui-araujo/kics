package main

__rego_metadata__ = {
  "id": "AWSRDS_SL_TRACK_NAME_PUBLIC",
  "title": "Redshift Serverless Workgroup track_name set to public",
  "description": "The track_name argument 'public' may expose logs publicly.",
  "severity": "LOW",
  "type": "Misconfiguration"
}

violation[{"msg": msg, "resource": rc.address}] {
  rc := input.resource_changes[_]
  rc.type == "aws_redshiftserverless_workgroup"
  after := rc.change.after
  after.track_name == "public"
  msg := sprintf("Resource '%s' sets track_name to 'public', potentially exposing logs publicly.", [rc.address])
}