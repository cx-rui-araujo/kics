package main

__rego_metadata__ := {"id":"KICS-0001","title":"Avoid using uri_fragment in WAFv2 field_to_match","description":"AWS WAF cannot inspect URI fragments. Including uri_fragment in field_to_match gives false sense of protection.","severity":"MEDIUM","type":"VULNERABILITY","license":"Apache-2.0"}

deny[msg] {
  resource := tfconfig.resource.aws_wafv2_rule_group[name]
  resource.rule[_].statement[0].byte_match_statement[0].field_to_match[0].uri_fragment
  msg := sprintf("WAFv2 Rule Group '%s' uses uri_fragment field_to_match, which is not supported by AWS WAF.", [name])
}