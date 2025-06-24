package terraform_aws_bedrockagent_agent_alias

__rule_name__ = "ensure_routing_configuration_is_set_on_alias"
__rule_id__ = "KICS-TERRAFORM-0000"
__rule_provider__ = "aws"
__rule_service__ = "bedrockagent"
__rule_short_description__ = "Ensure aws_bedrockagent_agent_alias has routing_configuration block"
__rule_long_description__ = "Missing routing_configuration can unintentionally remove alias routing, causing traffic to default or insecure endpoints when updates omit this block."
__rule_severity__ = "MEDIUM"
__rule_recommended_actions__ = "Add a routing_configuration block to aws_bedrockagent_agent_alias resources explicitly."
__rule_links__ = []

violation[resource] {
  resource := data.resources.aws_bedrockagent_agent_alias[_]
  not resource.block.get("routing_configuration")
}