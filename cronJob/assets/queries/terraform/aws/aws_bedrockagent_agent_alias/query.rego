package terraform

import data.tfconfig as tfconfig

deny[reason] {
  tfconfig.resource.aws_bedrockagent_agent_alias[res]
  not tfconfig.resource.aws_bedrockagent_agent_alias[res].routing_configuration
  reason := sprintf("Resource '%s' should include 'routing_configuration' to ensure proper alias routing", [res])
}