package kics.rules

violation[{"resource": rc.address, "message": "WAFv2 rule 'uri_fragment' match may be bypassed as browsers do not send URL fragments to servers."}] {
  rc := input.resource_changes[_]
  rc.type == "aws_wafv2_rule_group"
  rc.change.after.rules[_].statement[_].field_to_match.uri_fragment
}