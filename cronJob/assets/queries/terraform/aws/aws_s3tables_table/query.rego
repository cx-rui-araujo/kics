package terraform.queries.aws.s3tables_table

__rego_metadata__ = {
  'id': 'AWS999',
  'title': 'Ensure S3 Tables have encryption_configuration',
  'severity': 'HIGH',
  'type': 'VULNERABILITY'
}

deny[res] {
  resource := input.resource_changes[_]
  resource.type == 'aws_s3tables_table'
  after := resource.change.after
  not after.encryption_configuration
  res := {
    'message': 'S3 Table does not have encryption_configuration set. Data at rest may be unencrypted.'
  }
}
