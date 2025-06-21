package terraform.aws_wafv2_uri_fragment

__rego_metadata__ := {
    "id": "AWS119",
    "title": "WAFv2 rule group using uri_fragment only in field_to_match",
    "severity": "MEDIUM",
    "type": "VULNERABILITY",
    "labels": ["security", "aws", "wafv2"]
}

violation[resource] {
    resource := input.resource
    resource.type == "aws_wafv2_rule_group"
    some i
    rule := resource.values.rule[i]
    # Look for size_constraint_statement using only uri_fragment
    scs := rule.statement.size_constraint_statement
    scs.field_to_match.uri_fragment
}
