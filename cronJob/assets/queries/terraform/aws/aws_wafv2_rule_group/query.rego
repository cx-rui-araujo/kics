package waf

__rego_metadata__ := {
  "id": "KICS-0001",
  "title": "Use of uri_fragment in WAFv2 rule groups is ineffective",
  "severity": "LOW",
  "description": "The uri_fragment part of a request is not sent to the server and therefore cannot be inspected by AWS WAF, leading to a false sense of protection.",
  "category": "security"
}

violation[{
    "message": msg,
    "resource": resource.address
}] {
    resource := input.resource
    resource.type == "aws_wafv2_rule_group"
    some i
    rule := resource.arguments.rules[i]
    rule.statement.byte_match_statement.field_to_match.uri_fragment
    msg := sprintf("Resource '%s' uses uri_fragment in field_to_match which cannot be inspected by WAF", [resource.address])
}