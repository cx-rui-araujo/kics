package main

den y[msg] {
    rc := tfplan.resource_changes[_]
    rc.change.after.Type == "aws_s3tables_table"
    not rc.change.after.encryption_configuration
    msg := sprintf("aws_s3tables_table '%v' missing encryption_configuration, data may be stored unencrypted", [rc.address])
    msg
}