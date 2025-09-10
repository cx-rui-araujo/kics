package awsCloudwatchEventConnectionDefaultKMS

violation[resource] {
    resource := tfconfig.resource["aws_cloudwatch_event_connection"][resourceName]
    identifier := resource.values.kms_key_identifier
    startswith(identifier, "alias/aws/")
}