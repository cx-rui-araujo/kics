package terraform.AWS.ControlTowerControl

__rego_metadata__ := {
  "id": "AWSCTRLTWR_001",
  "title": "Ensure aws_controltower_control has parameters block",
  "severity": "MEDIUM",
  "type": "VIOLATION",
  "docs": {
    "recommendation": "Add a 'parameters' block to aws_controltower_control to avoid default insecure configuration."
  }
}

violation[resource] {
  resource := input.resource
  resource.Type == "aws_controltower_control"
  not resource.Configuration.parameters
}