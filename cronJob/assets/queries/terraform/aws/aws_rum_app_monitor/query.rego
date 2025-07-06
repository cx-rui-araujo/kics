package kics

violation[{
  "msg": msg,
  "resource": resource.address
}] {
  resource := input.resource_changes[_]
  resource.type == "aws_rum_app_monitor"
  after := resource.change.after
  (wildcardDomainList(after.domain_list) or missingDomain(after))
  msg := describe(after)
}

wildcardDomainList(list) {
  list
  some i
  glob.match("*.*", list[i], {"separator": "."})
}

missingDomain(after) {
  not after.domain
}

describe(after) = msg {
  missingDomain(after)
  msg = "The 'domain' field is missing, which may allow unintended domains."
}
describe(after) = msg {
  wildcardDomainList(after.domain_list)
  msg = sprintf("Wildcard entries found in 'domain_list': %v. This may allow unvalidated domains.", [after.domain_list])
}