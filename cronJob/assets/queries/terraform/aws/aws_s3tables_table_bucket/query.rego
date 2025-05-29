id: AWS012
metadata:
  name: "Ensure aws_s3tables_table_bucket has encryption_configuration"
  severity: "HIGH"
  description: "Detects aws_s3tables_table_bucket resources missing encryption_configuration, which may lead to unencrypted data storage."
  impact: "Data at rest in the table bucket may not be encrypted."
  resolution: "Add an encryption_configuration block to enable server-side encryption."

package aws_s3tables_table_bucket

__rego_metadata__ := {
  "id": "AWS012",
  "title": "aws_s3tables_table_bucket missing encryption_configuration",
  "severity": "HIGH",
  "type": "VULNERABILITY"
}

violation[output] {
  resource := input.resource
  resource.type == "aws_s3tables_table_bucket"
  not resource.values.encryption_configuration
  output := {
    "msg": sprintf("Resource '%s' does not define encryption_configuration", [resource.name]),
    "resource": resource
  }
}