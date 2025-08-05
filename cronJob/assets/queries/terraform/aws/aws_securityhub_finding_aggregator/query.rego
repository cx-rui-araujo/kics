package check

__rego_metadoc__ = {
  \"id\": \"KICS_AWS_SECURITYHUB_LINKING_MODE_NO_REGIONS\",
  \"title\": \"AWS Security Hub finding aggregator should not use NO_REGIONS linking_mode\",
  \"severity\": \"MEDIUM\",
  \"type\": \"VIOLATION\",
}

deny[issue] {
  resource := input.Resource
  resource.Type == \"aws_securityhub_finding_aggregator\"
  resource.Values.linking_mode == \"NO_REGIONS\"
  issue := {
    \"message\": sprintf(\"Resource '%s' has linking_mode set to NO_REGIONS, disabling regional aggregation\", [resource.Name]),
    \"startline\": resource.StartLine,
    \"endline\": resource.EndLine
  }
}