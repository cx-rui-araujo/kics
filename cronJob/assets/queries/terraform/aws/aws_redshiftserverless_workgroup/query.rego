package aws.redshiftserverless

violation[{"msg": msg, "resource": resource}] {
  resource := input.resource_changes[_]
  resource.type == "aws_redshiftserverless_workgroup"
  track := resource.change.after.track_name
  # Imaginary vulnerability: track_name starting with "secret_" may leak internal identifiers
  startswith(track, "secret_")
  msg := sprintf("Insecure track_name '%s' detected. Avoid using 'secret_' prefix.", [track])
}