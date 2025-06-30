package terraform.aws.redshift

__rego_metadata__ = {
  "id": "GENERIC001",
  "title": "Ensure secure prefix on Redshift Serverless workgroup track_name",
  "description": "Having an unvalidated or improperly prefixed track_name may lead to misrouting of usage data or unintended sharing of metrics.",
  "severity": "MEDIUM",
  "type": "Terraform Security Check"
}

violation[resource] {
  resource := input.resource_changes.aws_redshiftserverless_workgroup[_]
  after := resource.change.after
  # track_name is set but does not start with the required secure prefix
  after.track_name != null
  not startswith(after.track_name, "secure-")
  resource_address := resource.address
  resource = {
    "address": resource_address,
    "message": sprintf("aws_redshiftserverless_workgroup '%s' uses insecure track_name '%s'", [resource_address, after.track_name])
  }
}