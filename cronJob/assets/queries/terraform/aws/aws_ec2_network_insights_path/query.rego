package main

__rego_meta__ := {"id":"KICS-1234","title":"Missing filter_at_source.source_address in AWS EC2 network insights path","severity":"MEDIUM","type":"Misconfiguration"}

violation[resource] {
    resource := tfconfig.resources.aws_ec2_network_insights_path[resource_name]
    not resource.values.filter_at_source.source_address
    resource
}