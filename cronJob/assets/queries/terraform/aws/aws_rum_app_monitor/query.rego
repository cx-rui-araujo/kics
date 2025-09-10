package kics

default deny = false

den y {
  input.resource_type == "aws_rum_app_monitor"
  not input.change.after.domain_list
}

den y {
  input.resource_type == "aws_rum_app_monitor"
  some i
  wildcards := [d | d := input.change.after.domain_list[i]; contains(d, "*")]
  count(wildcards) > 0
}