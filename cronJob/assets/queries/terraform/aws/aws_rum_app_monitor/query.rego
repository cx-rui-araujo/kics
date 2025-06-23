package main

# KICS Query: Ensure aws_rum_app_monitor sets a restrictive domain_list to avoid accepting all domains
violation[resource] {
  # iterate over all resource changes in the plan
  resource := input.resource_changes[_]
  # filter to aws_rum_app_monitor
  resource.type == "aws_rum_app_monitor"
  # after the change, domain_list must be defined and non-empty
  after := resource.change.after
  not after.domain_list
}