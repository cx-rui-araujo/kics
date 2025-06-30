package main

__rego_metadata__ := {
  "id": "AWSRUM001",
  "title": "Require domain_list in aws_rum_app_monitor",
  "severity": "LOW",
  "type": "MISCONFIGURATION",
  "category": "Security",
  "version": "1.0"
}

deny[msg] {
  input.resource_changes[_] == {
    "address": addr,
    "type": "aws_rum_app_monitor",
    "change": {"after": after},
  }
  not after.domain_list
  msg := sprintf("Resource '%s' does not specify 'domain_list', potentially allowing unauthorized domains.", [addr])
}