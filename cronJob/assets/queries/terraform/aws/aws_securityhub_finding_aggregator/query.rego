package main

__rego_metadoc__ = {
  "id": "AWSXXX",
  "title": "Security Hub finding aggregator must not use NO_REGIONS linking_mode",
  "severity": "HIGH",
}

deny[{
    "msg": msg,
    "resource": res,
}] {
    res := input.block
    res.type == "resource"
    res.labels[0] == "aws_securityhub_finding_aggregator"
    attr := res.body.attributes.linking_mode
    attr.value == "NO_REGIONS"
    msg := sprintf("Resource '%s' uses linking_mode NO_REGIONS, which disables cross-region aggregation", [res.labels[1]])
}