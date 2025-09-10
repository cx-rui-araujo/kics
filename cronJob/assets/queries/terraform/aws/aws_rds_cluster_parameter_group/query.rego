package tfplan

import "strings"

__rego_metadoc__ := {
  "id": "AWS_RDS_COLLATION_MISMATCH",
  "title": "Invalid collation_server for aws_rds_cluster_parameter_group",
  "severity": "MEDIUM",
  "type": "VIOLATION"
}

deny[msg] {
  resource := tfplan.resource_changes[_]
  resource.type == "aws_rds_cluster_parameter_group"
  change := resource.change.after
  params := change.parameters
  param := params[_]
  param.name == "collation_server"
  not validCollation(param.value)
  msg := sprintf("Parameter 'collation_server' has invalid collation '%s'", [param.value])
}

validCollation(val) {
  strings.HasPrefix(val, "utf8")
  strings.HasSuffix(val, "_ci")
}