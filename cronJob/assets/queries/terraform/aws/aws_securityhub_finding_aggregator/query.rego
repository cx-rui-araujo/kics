package kics

deny[msg] {
    input.resource_blocks[i].type == "aws_securityhub_finding_aggregator"
    linking_mode := input.resource_blocks[i].attributes.linking_mode
    linking_mode.value == "NO_REGIONS"
    msg := sprintf("Security Hub finding aggregator '%s' has linking_mode set to NO_REGIONS, no regions will be aggregated", [input.resource_blocks[i].labels[0]])
}