package terraform.aws.securityhub

deny[msg] {
  resource := input.resource
  resource.Type == "aws_securityhub_finding_aggregator"
  resource.Config.linking_mode == "NO_REGIONS"
  msg := sprintf("aws_securityhub_finding_aggregator '%s' uses NO_REGIONS linking_mode, disabling regional aggregation and potentially missing findings", [resource.Name])
}