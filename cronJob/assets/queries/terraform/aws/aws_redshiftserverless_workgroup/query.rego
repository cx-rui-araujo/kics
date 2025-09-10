package main

violation[entry] {
  resource := input.resource_changes[_]
  resource.type == "aws_redshiftserverless_workgroup"
  track := resource.change.after.track_name
  contains(track, "public")
  entry := {
    "msg": sprintf("Workgroup '%s' uses insecure track_name '%s', which may expose sensitive metrics", [resource.address, track]),
    "resource": resource.address
  }
}