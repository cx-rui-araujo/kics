package main

__rego_metadata__ := {
  "id": "AWS013",
  "title": "WAFv2 Rule Group uses uri_fragment in field_to_match",
  "description": "Matching on uri_fragment in WAFv2 rule group is ineffective as URI fragments are not sent to the server, leading to rules not triggering.",
  "severity": "MEDIUM",
  "platform": "terraform",
  "recommended_actions": "Remove uri_fragment from field_to_match or use a valid match field",
  "references": ["https://docs.aws.amazon.com/waf/latest/APIReference/API_FieldToMatch.html"]
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_wafv2_rule_group"
  after := resource.change.after
  some i
  rules := after.attributes.rules
  rules[i].statement.byte_match_statement.field_to_match.uri_fragment
  msg := sprintf("WAFv2 rule_group '%s' includes uri_fragment in field_to_match, which is ineffective.", [resource.address])
}