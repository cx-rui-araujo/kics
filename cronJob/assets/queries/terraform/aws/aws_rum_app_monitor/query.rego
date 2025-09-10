package terraform

violation[{
  "msg": msg,
  "resource": res.address
}] {
  res := input.resource_changes[_]
  res.type == "aws_rum_app_monitor"
  after := res.change.after
  (
    // domain_list added but empty -> allows unrestricted domains
    (after.domain_list == [])
    // domain marked optional but missing -> no domain constraint
    or not after.domain
  )
  msg := sprintf("RUM App Monitor '%s' permits unintended domains: domain_list=%v, domain=%v", [res.address, after.domain_list, after.domain])
}