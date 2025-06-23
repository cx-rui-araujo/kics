package kicsawswafv2

__rego_metadata__ := {
  "id": "KICS-001",
  "title": "AWS WAFv2 rule group uses uri_fragment field_to_match",
  "severity": "LOW",
  "type": "MISCONFIGURATION"
}

# Detect any object containing uri_fragment
has_uri_fragment(x) {
  x.uri_fragment
}

# Recursively walk through configuration to find uri_fragment
walk(x) = true {
  has_uri_fragment(x)
}
walk(x) = result {
  is_object(x)
  some k
  walk(x[k]) = result
}

# Violation when uri_fragment is used in aws_wafv2_rule_group
violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_wafv2_rule_group"
  walk(resource.change.after)
}