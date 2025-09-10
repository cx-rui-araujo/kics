package main

import data

violation[{"msg": msg, "resource": resource.address}] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3tables_table"
    after := resource.change.after
    not after.encryption_configuration
    msg := sprintf("The aws_s3tables_table '%s' does not have encryption_configuration set. Without it, data at rest may not be encrypted, leading to potential data exposure.", [resource.address])
}