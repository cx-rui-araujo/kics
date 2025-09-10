package main

__rego_metadata__ := {
  'id': 'AWS003',
  'title': 'Ensure aws_s3tables_table uses encryption_configuration',
  'severity': 'HIGH',
  'type': 'VULNERABILITY',
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == 'aws_s3tables_table'
  after := resource.change.after
  not after.encryption_configuration
  msg := sprintf('Resource %s is missing encryption_configuration, data at rest is unencrypted', [resource.address])
}
