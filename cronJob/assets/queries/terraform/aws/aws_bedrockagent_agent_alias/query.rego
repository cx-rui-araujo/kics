package kics

import data.terraform.tfplan as tfplan

# Violation if aws_bedrockagent_agent_alias does not explicitly configure routing_configuration
violation[resource] {
  resource := tfplan.resource_changes[_]
  resource.type == "aws_bedrockagent_agent_alias"
  action := resource.change.actions[_]
  action == "create"  # or "update"
  not resource.change.after.routing_configuration
}