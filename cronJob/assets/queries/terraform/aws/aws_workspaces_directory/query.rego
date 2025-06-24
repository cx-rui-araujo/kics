package awsWorkspaces

__rego_metadata__ := {"id":"KICS-NEW-001","title":"WorkSpaces Directory Weak Identity Type","severity":"MEDIUM","description":"Detect aws_workspaces_directory resources with user_identity_type set to PASSWORD, which may be insecure and prone to brute force attacks.","source":"custom/aws/workspaces_directory_identity_type.rego","recommended_actions":"Use SERVICE_MANAGED identity type instead of PASSWORD."}

violation[resource] {
	resource := input.resource.aws_workspaces_directory[_]
	resource.user_identity_type == "PASSWORD"
}