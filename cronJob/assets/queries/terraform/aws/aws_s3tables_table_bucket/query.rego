package main

violation[{"resource": r, "message": msg}] {
    r := input.resource[_]
    r.type == "aws_s3tables_table_bucket"
    enc := r.values.encryption_configuration[_]
    rule := enc.rule[_]
    default := rule.apply_server_side_encryption_by_default[_]
    default.sse_algorithm != "aws:kms"
    msg := sprintf("S3 Table Bucket %v uses an unsupported SSE algorithm: %v. Use AWS KMS instead.", [r.name, default.sse_algorithm])
}