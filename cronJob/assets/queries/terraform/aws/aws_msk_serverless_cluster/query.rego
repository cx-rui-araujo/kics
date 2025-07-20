package kics

import data.terraform.tfconfig as tfconfig

# KICS AWS MSK BKRSLS1: detect usage of bootstrap_brokers_sasl_iam without IAM policy
violation[{"resource": res.address, "message": "bootstrap_brokers_sasl_iam set without proper IAM restrictions may allow unauthorized access"}] {
  res := tfconfig.resource_blocks["aws_msk_serverless_cluster"][_]
  res.attributes.bootstrap_brokers_sasl_iam.value == "true"
}
