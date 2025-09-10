package terraform.aws.AppFlow.SalesforceBulkAPIExfil

__rego_metadata__ := {
    "id": "AWS.AppFlow.001",
    "title": "Salesforce Bulk API V2 usage can lead to data exfiltration",
    "severity": "HIGH",
    "description": "Using BULK_API_V2 for Salesforce data_transfer_api allows high-volume data exfiltration by malicious actors.",
    "recommended_actions": "Use REST_API or restrict usage of Bulk API V2 in AppFlow.",
    "reference_id": "aws-appflow-001",
    "tags": ["AWS", "AppFlow", "Salesforce"]
}

violation[issue] {
    resource := input.resource_changes[_]
    resource.type == "aws_appflow_flow"
    after := resource.change.after
    after.destination_flow_config[0].destination_connector_properties[0].salesforce[0].data_transfer_api == "BULK_API_V2"
    issue := {
        "message": sprintf("Resource '%s' uses BULK_API_V2 for Salesforce data_transfer_api, posing a potential data exfiltration risk.", [resource.address]),
        "resource": resource.address
    }
}