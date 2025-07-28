package checkawssecurityhubfindingaggregator

deny[msg] {
  resource := tfconfig.resource.aws_securityhub_finding_aggregator[_]
  resource.values.linking_mode == "NO_REGIONS"
  msg := "aws_securityhub_finding_aggregator 'linking_mode' set to 'NO_REGIONS' disables region aggregation, leading to blind spots."
}