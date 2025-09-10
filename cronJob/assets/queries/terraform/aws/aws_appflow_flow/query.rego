package terraform.aws_appflow

__rego_metadata__ := {
    "id": "KICS-42479",
    "title": "Avoid using Salesforce Bulk API for data transfer",
    "severity": "HIGH",
    "type": "VULNERABILITY"
}

violation[{"msg": msg, "resource": address}] {
    resource := input.resource_config.aws_appflow_flow[_]
    address := sprintf("%v.%v", [resource.module_path, resource.name])
    dest := resource.destination_flow_config[0].destination_connector_properties[0].salesforce[0]
    dest.data_transfer_api == "bulk"
    msg := sprintf("aws_appflow_flow '%v' uses 'bulk' for data_transfer_api, which may lead to unmonitored data exfiltration.", [address])
}