package kics

violation[{"msg": msg, "resource": resource.address}] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table_bucket"
  config := resource.change.after
  # Imaginary vulnerability: encryption_configuration declared but missing actual encryption rules
  config.encryption_configuration
  not config.encryption_configuration.server_side_encryption_configuration.rules[_]
  msg := "Imaginary vulnerability: 'encryption_configuration' defined without any 'server_side_encryption_configuration.rules', leading to insecure defaults."
}