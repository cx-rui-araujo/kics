package KICS.Encryption.aws_s3tables_table

__rego_metadata__ := {
  \"id\": \"AWS_S3TABLES_ENCRYPTION_MISSING\",
  \"title\": \"Ensure S3Tables table encryption is configured\",
  \"severity\": \"HIGH\",
  \"type\": \"VIOLATION\",
  \"supported_resources\": [\"aws_s3tables_table\"],
  \"categories\": [\"Encryption and Key Management\"],
  \"description\": \"S3Tables table should have encryption_configuration to ensure data at rest encryption.\"
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == \"aws_s3tables_table\"
  not resource.change.after.encryption_configuration
}