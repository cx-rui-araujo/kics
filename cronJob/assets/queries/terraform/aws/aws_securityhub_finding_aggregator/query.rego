package main

__rego_metadata__ = {
  "id": "CUSTOM_AWS_SECURITYHUB_AGGREGATOR_NO_REGIONS",
  "title": "Security Hub Finding Aggregator linking_mode set to NO_REGIONS",
  "severity": "HIGH",
  "type": "MISCONFIGURATION",
}

deny[message] {
  resource := input.Root.Modules[_].Resources[_]
  resource.Type == "aws_securityhub_finding_aggregator"
  resource.Values.linking_mode == "NO_REGIONS"
  message := sprintf("Resource '%s' uses NO_REGIONS for linking_mode, disabling regional aggregation", [resource.Name])
}