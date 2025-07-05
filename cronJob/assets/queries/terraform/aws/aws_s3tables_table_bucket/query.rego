package main

__rego_metadata__ = {
    "id": "KICS_AWS_S3TABLES_TABLE_BUCKET_ENCRYPTION",
    "title": "AWS S3Tables table bucket should configure encryption_configuration with KMS",
    "description": "An S3Tables table bucket without a KMS-backed encryption_configuration is unencrypted or uses default encryption, which may not meet security requirements.",
    "severity": "MEDIUM",
    "type": "VIOLATION"
}

violation[message] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3tables_table_bucket"
    after := resource.change.after
    # encryption_configuration block must exist
    after.encryption_configuration == null
    message := sprintf("Resource '%s' does not configure encryption_configuration, data may be unencrypted or use default S3-managed encryption.", [resource.address])
}

violation[message] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3tables_table_bucket"
    after := resource.change.after
    enc := after.encryption_configuration
    enc != null
    # kms_key_arn must be provided for AWS KMS encryption
    not enc.kms_key_arn
    message := sprintf("Resource '%s' uses encryption_configuration without specifying kms_key_arn, default encryption may be insufficient.", [resource.address])
}