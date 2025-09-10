package main
import data.terraform as tf
violation[cluster] {
  cluster := tf.resource["aws_msk_serverless_cluster"][name]
  cluster.attributes.bootstrap_brokers_sasl_iam.value == true
}