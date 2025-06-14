package kics

__rego_metadata__ := {
  "id": "AWS.WorkSpacesDirectory.ActiveDirectoryPublic",
  "title": "WorkSpaces Directory Active Directory endpoint should not be publicly accessible",
  "severity": "HIGH",
  "type": "VULNERABILITY",
  "description": "Misconfigured active_directory_config.publicly_accessible allows unrestricted network access to the Active Directory endpoint.",
  "enabled": true
}

denied[res] {
  input.kind == "terraform"
  rc := input.resource_changes[_]
  rc.type == "aws_workspaces_directory"
  after := rc.change.after
  # Check for public AD endpoint
  adcfg := after.active_directory_config
  adcfg != null
  adcfg[0].publicly_accessible == true
  res := {
    "rule_id": __rego_metadata__.id,
    "message": sprintf("Resource '%s' configures a public Active Directory endpoint", [rc.address]),
    "severity": __rego_metadata__.severity
  }
}