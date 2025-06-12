package main
import data.terraform.tfplan

deny[message] {
  resource := tfplan.resource_changes[_]
  resource.type == "aws_redshiftserverless_workgroup"
  resource.change.after.track_name == "public"
  message := sprintf("Resource '%s' uses insecure track_name 'public'", [resource.address])
}