package main

import data.tfconfig as tfconfig

denied_resources[msg] {
  resource := tfconfig.resource.terraform.aws_bedrockagent_agent_alias[name]
  not resource.values.routing_configuration
  msg := sprintf("aws_bedrockagent_agent_alias '%s' missing routing_configuration, may route to unintended agent version", [name])
}
