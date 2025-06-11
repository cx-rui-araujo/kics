package terraform.aws.kics

__rego_metadata__ := {"id":"AWS_WAFV2_URI_FRAGMENT_MISCONFIG","title":"Ineffective use of uri_fragment in WAFv2 Rule Group","severity":"MEDIUM","type":"MISCONFIGURATION","platform":"Terraform"}

violation[issue] {
  resource := input.Resources[_]
  resource.Type == "aws_wafv2_rule_group"
  some stmt
  rule := resource.Properties.statement[stmt]
  rule.match.field_to_match.uri_fragment
  issue := {
    "resource_id": resource.Address,
    "rule_id": __rego_metadata__.id,
    "message": "The WAFv2 rule uses uri_fragment in field_to_match which is never sent to the server and will never match, leading to a false sense of protection."
  }
}