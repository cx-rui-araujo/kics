package tfaws_s3tables_table_encryption

meta = {
  "id": "AWS0001",
  "title": "Ensure S3Tables Table has encryption_configuration",
  "severity": "HIGH",
  "confidence": "MEDIUM"
}

violation[res] {
  res := input.resource.aws_s3tables_table[_]
  not res.encryption_configuration
}
