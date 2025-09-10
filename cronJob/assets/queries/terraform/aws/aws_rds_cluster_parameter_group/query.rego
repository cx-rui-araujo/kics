package main

import data.terraform.plan.resource_changes

deny[rc] {
  rc := resource_changes[_]
  rc.address == "aws_rds_cluster_parameter_group"
  after := rc.change.after.parameters[_]
  after.name == "collation_server"
  weakCollations := {"latin1_swedish_ci", "SQL_Latin1_General_CP1_CI_AS"}
  weakCollations[after.value]
}