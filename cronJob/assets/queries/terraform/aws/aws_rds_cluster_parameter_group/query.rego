package terraform.aws.rds

import data.tfconfig as tfconfig

# Deny RDS cluster parameter groups using case-insensitive collations
violation[resource] {
  resource := tfconfig.resource[res]           # iterate resources
  resource.type == "aws_rds_cluster_parameter_group"

  # find the collation_server parameter
  params := resource.values.parameters
  param := params[_]
  param.name == "collation_server"

  # flag potentially unsafe case-insensitive collations
  endswith(param.value, "_ci")
}
