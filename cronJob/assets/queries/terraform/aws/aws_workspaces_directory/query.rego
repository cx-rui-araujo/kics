id: KICS-42330
title: "Insecure AWS WorkSpaces Directory Configuration"
severity: MEDIUM
description: "Detect insecure or default configurations in aws_workspaces_directory new fields."
impact: "Misconfigured AWS WorkSpaces directories may expose sensitive data or allow unauthorized access."
resolution: "Review and update the WorkSpaces directory configurations to use secure and non-default values."
providers: ["terraform"]
resources: ["aws_workspaces_directory"]
---
package aws.workspaces_directory

import data.tfconfig

# 1. user_identity_type should not be ROOT
violation[{"msg": msg, "resource": resource.name}] {
  resource := tfconfig.resource["aws_workspaces_directory"][_] 
  resource.config.user_identity_type[0] == "ROOT"
  msg = "aws_workspaces_directory user_identity_type is set to ROOT; insecure elevation risk."
}

# 2. directory_id must be provided
violation[{"msg": msg, "resource": resource.name}] {
  resource := tfconfig.resource["aws_workspaces_directory"][_]  
  not resource.config.directory_id
  msg = "aws_workspaces_directory missing directory_id; defaults to an insecure directory may be used."
}

# 3. workspace_type should not be AUTOMATIC
violation[{"msg": msg, "resource": resource.name}] {
  resource := tfconfig.resource["aws_workspaces_directory"][_]  
  resource.config.workspace_type[0] == "AUTOMATIC"
  msg = "aws_workspaces_directory workspace_type set to AUTOMATIC; requires manual assignment for stricter control."
}

# 4. workspace_directory_name should not start with 'default'
violation[{"msg": msg, "resource": resource.name}] {
  resource := tfconfig.resource["aws_workspaces_directory"][_]  
  name := resource.config.workspace_directory_name[0]
  startswith(name, "default")
  msg = sprintf("aws_workspaces_directory workspace_directory_name '%s' starts with 'default'; use a unique name.", [name])
}

# 5. workspace_directory_description should not contain sensitive keywords
violation[{"msg": msg, "resource": resource.name}] {
  resource := tfconfig.resource["aws_workspaces_directory"][_]  
  desc := resource.config.workspace_directory_description[0]
  contains(desc, "confidential")
  msg = "aws_workspaces_directory workspace_directory_description contains 'confidential'; avoid embedding sensitive info."
}

# 6. active_directory_config.simple_ad.password should not be default
violation[{"msg": msg, "resource": resource.name}] {
  resource := tfconfig.resource["aws_workspaces_directory"][_]  
  cfg := resource.config.active_directory_config[0]
  cfg.simple_ad.password[0] == "Passw0rd!"
  msg = "aws_workspaces_directory active_directory_config.simple_ad.password is the known default 'Passw0rd!'; insecure."
}