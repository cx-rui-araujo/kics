package main

violation[{"msg": msg}] {
  input.resource_changes[_] = rc
  rc.type == "aws_rum_app_monitor"
  after := rc.change.after
  after.domain_list
  domain := after.domain_list[_]
  startswith(domain, "*")
  msg := sprintf("Wildcard domain detected in aws_rum_app_monitor.domain_list: %v", [domain])
}