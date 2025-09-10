package main

import data.tfconfig

violation[{"msg": msg, "resource": resource_address}] {
    resource := tfconfig.resource[resource_address]
    resource.type == "aws_s3tables_table_bucket"
    not has_kms(resource.values.encryption_configuration)
    msg := sprintf("Resource %v should enforce AWS KMS encryption for table bucket", [resource_address])
}

has_kms(conf) {
    alg := conf[0].server_side_encryption_configuration[0].rule[0].apply_server_side_encryption_by_default[0].sse_algorithm
    alg == "aws:kms"
}