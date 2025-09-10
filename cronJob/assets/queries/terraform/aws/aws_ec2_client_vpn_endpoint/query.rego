package terraform
import data.terraform as tf

__rego_metadoc__ := {
  \"id\": \"KICS-0001\",
  \"title\": \"Ensure strict route enforcement is enabled for AWS EC2 Client VPN endpoint\",
  \"severity\": \"MEDIUM\",
  \"type\": \"Security Best Practices\"
}

violation[resource] {
  resource := tf.module_resources.aws_ec2_client_vpn_endpoint[_]
  options := resource.values.client_route_enforcement_options
  options[0].enable_strict_enforcement == false
}