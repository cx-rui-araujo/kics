package main

import data.tfplan

# KICS query to detect MSK Serverless clusters with SASL IAM brokers enabled without further restrictions
violation[cluster] {
  cluster := tfplan.resource_changes[_]
  cluster.type == "aws_msk_serverless_cluster"
  cluster.change.after.bootstrap_brokers_sasl_iam == true
}
