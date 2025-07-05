package kics

deny[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_redshiftserverless_workgroup"
  args := resource.change.after
  track := args.track_name
  startswith(track, "public-")
}