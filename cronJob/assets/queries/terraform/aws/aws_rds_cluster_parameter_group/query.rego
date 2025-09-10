package kics

import data

__rego_metadata__ := {
  "id": "CUSTOM_RDS_COLLATION_MISMATCH",
  "title": "Invalid collation_server for character_set",
  "severity": "HIGH",
  "type": "Misconfiguration"
}

violation[message] {
  # iterate over resource changes in the plan
  input.resource_changes[_] = change
  change.type == "aws_rds_cluster_parameter_group"

  # extract parameters
  params := change.change.after
  col := params.collation_server
  cs := params.character_set

  # both must be set
  cs != ""
  col != ""

  # check validity against allowed mapping
  not valid[cs][col]

  # build violation message
  message := sprintf("Invalid collation_server '%s' for character_set '%s'", [col, cs])
}

# define valid collation sets for each charset
valid = {
  "utf8": {"utf8_general_ci", "utf8_unicode_ci"},
  "latin1": {"latin1_swedish_ci"},
  "utf8mb4": {"utf8mb4_general_ci", "utf8mb4_unicode_ci"}
}