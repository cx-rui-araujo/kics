package main

__rego_metadata__ := {
    "id": "AWS_APPFLOW_001",
    "title": "Insecure Salesforce data_transfer_api usage",
    "severity": "HIGH",
    "category": "security/aws/appflow"
}

violation[output] {
    resource := input.resource_changes[_]
    resource.type == "aws_appflow_flow"
    after := resource.change.after
    props := after.destination_flow_config.destination_connector_properties.salesforce
    props.data_transfer_api == "REST"
    output := {
        "msg": sprintf("aws_appflow_flow '%s' uses insecure data_transfer_api 'REST', consider using 'BULK'", [resource.address]),
        "resource": resource.address
    }
}