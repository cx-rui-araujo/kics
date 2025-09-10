package aws_rum

violation[{"msg": msg, "resource": res.address}] {
  res := input.resource_changes[_]
  res.type == "aws_rum_app_monitor"
  after := res.change.after
  domains := after.domain_list
  some i
  d := domains[i]
  contains(d, "*")
  msg := sprintf("Wildcard domain '%s' in domain_list for RUM app monitor '%s'", [d, res.address])
}