package tfplan

__rego_metadata__["id"] = "KICS-AWS-123"
__rego_metadata__["title"] = "Ensure filter_at_source.source_address is specified on aws_ec2_network_insights_path"
__rego_metadata__["severity"] = "HIGH"
__rego_metadata__["type"] = "VULNERABILITY"

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_ec2_network_insights_path"
    after := resource.change.after
    after.filter_at_source
    not after.filter_at_source.source_address
    msg = sprintf("Resource '%s' has unspecified filter_at_source.source_address, potentially allowing unrestricted traffic", [resource.address])
}
