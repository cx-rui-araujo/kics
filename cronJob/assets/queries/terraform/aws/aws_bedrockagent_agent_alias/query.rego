package terraform.security.aws

import data.terraform.tfconfig as tfconfig

deny[res] {
  resource := tfconfig.resource_blocks[resName]
  resource.type == "aws_bedrockagent_agent_alias"
  not resource.body.routing_configuration
  res := {
    "resource": sprintf("%s.%s", [resource.type, resName]),
    "message": "Missing 'routing_configuration' block in aws_bedrockagent_agent_alias may route traffic to unintended model versions."
  }
}