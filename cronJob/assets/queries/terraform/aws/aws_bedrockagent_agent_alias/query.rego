package tfplan

import data.tfplan

# Deny when routing_configuration is omitted on aws_bedrockagent_agent_alias
violation[{"msg": msg, "resource": address}] {
  rc := data.tfplan.resource_changes[_]
  rc.type == "aws_bedrockagent_agent_alias"
  rc.change.after.routing_configuration == null
  address := rc.address
  msg := sprintf("aws_bedrockagent_agent_alias '%s' has no routing_configuration defined, potentially allowing uncontrolled version updates", [address])
}