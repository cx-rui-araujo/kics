package main

__rego_metadata__ := {
  "id": "WAFV2_URI_FRAGMENT",
  "title": "Avoid using uri_fragment in AWS WAFv2 Rule Group",
  "severity": "MEDIUM",
  "type": "MISCONFIGURATION"
}

denied[message] {
  # Iterate over all aws_wafv2_rule_group resources
  resource := data.tree.modules[].resources[_]
  resource.type == "aws_wafv2_rule_group"

  # Examine each instance of the rule group
  instance := resource.instances[_]

  # Check each rule block for uri_fragment in field_to_match
  rules := instance.attributes.rules[_]
  stmt_keys := [k | k := rules.statement[_]]
  some key
  stmt := rules.statement[key]
  field := stmt.field_to_match
  field.uri_fragment

  # Generate violation message
  message := sprintf("aws_wafv2_rule_group '%s' uses uri_fragment in field_to_match, which is ineffective", [resource.name])
}
