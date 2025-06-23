package main

__rego_metadata__ := {
    "id": "CKV_AWS_999",
    "title": "SecurityHub finding aggregator should not use NO_REGIONS linking_mode",
    "severity": "MEDIUM",
    "type": "VIOLATION"
}

deny[msg] {
    resource := input.resource_config.aws_securityhub_finding_aggregator[_]
    resource.linking_mode == "NO_REGIONS"
    addr := resource.address
    msg := sprintf("SecurityHub finding aggregator '%s' is configured with NO_REGIONS linking_mode, resulting in no regions being aggregated", [addr])
}