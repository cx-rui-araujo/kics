package main
import "tfplan"

# AWS S3Tables table without encryption configuration
violation[resource] {
    resource := tfplan.resource_changes.aws_s3tables_table[_]
    resource.change.after.encryption_configuration == null
}