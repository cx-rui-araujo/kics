package terraform.rules.awsRedshiftServerlessWorkgroup
import data.terraform as tf
# Detect insecure default track_name in aws_redshiftserverless_workgroup
violation[issue] {
  resource := tf.resource_changes[_]
  resource.type == "aws_redshiftserverless_workgroup"
  resource.change.after.track_name == "default"
  issue := {
    "msg": sprintf("Resource '%s' uses insecure default track_name 'default'", [resource.address]),
    "resource": resource.address
  }
}