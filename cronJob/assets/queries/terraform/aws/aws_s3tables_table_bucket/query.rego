package terraform

violation[{"msg": msg, "resource": name}] {
  resource := tfconfig.resource["aws_s3tables_table_bucket"][name]
  not resource.encryption_configuration
  msg := sprintf("Resource '%s' does not configure encryption_configuration", [name])
}