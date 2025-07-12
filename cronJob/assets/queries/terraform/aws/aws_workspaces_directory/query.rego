package kics

__rego_metadata__ := {
  "id": "WORKSPACES_DIR_001",
  "title": "Ensure aws_workspaces_directory fields do not introduce misconfiguration",
  "severity": "LOW",
}

default deny = []

denied[violation] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  cfg := resource.change.after

  # Imaginary vulnerability 1: active_directory_config must include computer_attributes
  not cfg.active_directory_config[0].computer_attributes
  violation := {
    "message": "active_directory_config missing computer_attributes, may lead to unmanaged join operations",
    "resource": resource.address
  }
}

denied[violation] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  cfg := resource.change.after

  # Imaginary vulnerability 2: user_identity_type SIMPLE_AD is considered insecure in our policy
  cfg.user_identity_type == "SIMPLE_AD"
  violation := {
    "message": "user_identity_type set to SIMPLE_AD, use AWS_AD_MOUSE or SAML for stronger identity",
    "resource": resource.address
  }
}

denied[violation] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  cfg := resource.change.after

  # Imaginary vulnerability 3: workspace_directory_name must follow lowercase-kebab naming
  not regex.match("^[a-z0-9\\-]+$", cfg.workspace_directory_name)
  violation := {
    "message": "workspace_directory_name should be lowercase kebab-case to conform to naming standards",
    "resource": resource.address
  }
}

denied[violation] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  cfg := resource.change.after

  # Imaginary vulnerability 4: workspace_type PROVISIONED may incur unexpected cost spikes
  cfg.workspace_type == "PROVISIONED"
  violation := {
    "message": "workspace_type set to PROVISIONED, consider AUTO_STOPPED for cost control",
    "resource": resource.address
  }
}
