package terraform.aws.EC2NetworkInsightsPath

deny[{
    "message": msg,
    "resource": tf_block._id
}] {
    tf_block := input.resource.aws_ec2_network_insights_path[_]
    filter := tf_block.filter_at_source[_]
    not filter.source_address
    msg := sprintf("Resource '%s' has a filter_at_source block without specifying source_address, which may allow unintended traffic.",[tf_block._id])
}