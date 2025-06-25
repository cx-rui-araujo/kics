package terraform

__rego_metadata__ := {
  "id": "KICS_AWS_RDS_CLUSTER_PARAMETER_GROUP_COLLATION_MISMATCH",
  "version": "1.0.0",
  "title": "RDS cluster parameter group uses a collation_server that does not match its character_set",
  "description": "Ensures that collation_server and character_set parameters are consistent to avoid runtime errors or misconfigurations.",
  "severity": "MEDIUM",
  "type": "Misconfiguration",
}

deny[violation] {
  resource := input.resource_changes[_]
  resource.type == "aws_rds_cluster_parameter_group"
  after := resource.change.after
  char_set := after.parameters.character_set
  collation := after.parameters.collation_server
  # flag mismatch: collation must start with the same base as character_set
  not startswith(collation, char_set)
  violation := {
    "message": sprintf("Parameter group '%s' has collation_server '%s' not matching character_set '%s'", [resource.name, collation, char_set])
  }
}