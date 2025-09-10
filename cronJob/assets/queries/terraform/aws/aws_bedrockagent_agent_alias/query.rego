package main

import data.tfconfig

deny[msg] {
  resource := tfconfig.resource
  resource.Type == "aws_bedrockagent_agent_alias"
  not resource.Config.routing_configuration
  msg := "Missing explicit routing_configuration on aws_bedrockagent_agent_alias allows fallback routing to older versions, possibly bypassing security updates."
}