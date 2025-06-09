package terraform.aws.bedrockagent

import data.terraform.resources as resources

violation[output] {
  resource := resources[_]
  resource.type == "aws_bedrockagent_agent_alias"
  not resource.values.routing_configuration
  output := {
    "resource": resource.address,
    "message": "aws_bedrockagent_agent_alias missing routing_configuration. Without explicit config, updates may remove routing settings and break alias routing."}
}