package terraform.security.aws

import data.terraform as tf

__rego_metadata__ := {
    "id": "AWS.WAFV2.RuleGroup.UriFragmentOnly",
    "title": "WAFv2 Rule Group should not match only URI fragment",
    "description": "Matching only the URI fragment in a WAFv2 rule group can be bypassed because URI fragments are not sent to the server, allowing malicious requests to pass through.",
    "severity": "MEDIUM",
    "platform": "Terraform",
    "recommended_actions": "Avoid configuring rules that match only on uri_fragment. Include other match fields such as body or query_string."
}

deny[issue] {
  resource := tf.resource_changes[_]
  resource.type == "aws_wafv2_rule_group"
  after := resource.change.after_block
  rules := after.rules
  rule := rules[_]
  stmt := rule.statement[_]
  # Check for any statement that matches only on uri_fragment
  stmt.field_to_match.uri_fragment
  not stmt.field_to_match.body
  not stmt.field_to_match.query_string
  not stmt.field_to_match.headers
  issue := {
    "resource": resource.address,
    "rule_name": rule.name,
    "message": sprintf("Rule group '%s' matches only URI fragment, which is not sent to the server and can be bypassed.", [rule.name])
  }
}