package aws.s3tables.encryption

__rego_metadoc__
title: "Ensure aws_s3tables_table has encryption_configuration"
description: "Detects aws_s3tables_table resources missing encryption_configuration, which may leave data unencrypted at rest."
impact: "Sensitive data could be exposed if encryption is not enabled."
severity: "HIGH"
rule_id: "AWS_S3TABLES_001"
__rego_metadoc_end__

import data.terraform.tfconfig as tfconfig

violation[resource] {
  resource := tfconfig.module.resources[_]
  resource.type == "aws_s3tables_table"
  not resource.values.encryption_configuration
}