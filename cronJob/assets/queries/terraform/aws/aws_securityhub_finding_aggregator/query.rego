package terraform.aws.securityhub

# Detect when Security Hub finding aggregator is configured with NO_REGIONS linking mode
# which disables cross-region aggregation and may lead to missing findings.
deny[msg] {
  resource := input.resource[_]
  resource.type == "aws_securityhub_finding_aggregator"
  instance := resource.instances[_]
  mode := instance.attributes.linking_mode
  mode == "NO_REGIONS"
  msg = "Security Hub finding aggregator uses NO_REGIONS linking mode, disabling cross-region aggregation and risking missing findings"
}