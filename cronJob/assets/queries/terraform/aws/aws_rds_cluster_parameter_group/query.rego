package rules.aws.rds

import data.terraform as tf

# Detect mismatched collation_server and character_set in RDS cluster parameter groups
violation[resource] {
  resource := tf.resources["aws_rds_cluster_parameter_group"][_]
  params := resource.values.parameters
  col := params.collation_server
  cs := params.character_set
  col != null
  cs != null
  not valid[cs][col]
}

valid := {
  "utf8": {"utf8_general_ci"},
  "utf8mb4": {"utf8mb4_general_ci", "utf8mb4_unicode_ci"}
}