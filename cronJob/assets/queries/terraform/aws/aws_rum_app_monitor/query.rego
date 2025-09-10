package main

violation[{"msg": msg, "resource": rc.address}] {
  rc := input.resource_changes[_]
  rc.type == "aws_rum_app_monitor"
  rc.change.after.domain_list != null
  msg := sprintf("aws_rum_app_monitor '%s' uses domain_list allowing potential malicious domains", [rc.address])
}