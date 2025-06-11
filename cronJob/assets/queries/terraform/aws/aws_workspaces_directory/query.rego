package aws

__rego_metadata__ := {
    "id": "AWS_KICS_42330",
    "title": "WorkSpaces Directory must define an encrypted Active Directory config",
    "severity": "HIGH",
    "type": "Vulnerability",
    "uri": "terraform.aws_workspaces_directory",
    "description": "Without an explicit KMS key in active_directory_config, WorkSpaces directory data may be unencrypted at rest.",
    "source": {
        "provider": "terraform",
        "url": "https://docs.aws.amazon.com/workspaces/latest/adminguide/manage-workspaces-pools-directory.html"
    }
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  after := resource.change.after
  # Imaginary vulnerability: missing encryption key in AD config
  not after.active_directory_config
  resource
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  after := resource.change.after
  active := after.active_directory_config
  # Imaginary vulnerability: missing KMS key
  active
  not active.kms_key_id
  resource
}