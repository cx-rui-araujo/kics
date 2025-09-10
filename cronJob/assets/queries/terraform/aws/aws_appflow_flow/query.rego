package main

__rego_metadata__ = {
    "id": "KICS-EXAMPLE-AWS-001",
    "title": "Ensure aws_appflow_flow does not use BATCH data_transfer_api",
    "severity": "MEDIUM",
    "type": "VULNERABILITY"
}

deny[{
    "message": msg,
    "resource": resource.address,
}] {
    resource := input.resource_changes[_]
    resource.type == "aws_appflow_flow"
    after := resource.change.after.destination_flow_config.destination_connector_properties.salesforce
    after.data_transfer_api == "BATCH"
    msg := sprintf("Resource %s uses insecure data_transfer_api: %s", [resource.address, after.data_transfer_api])
}
