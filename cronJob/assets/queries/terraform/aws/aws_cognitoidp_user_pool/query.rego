package main

__rego_metadoc__ := {
  "id": "AWS9002",
  "version": "1.0.0",
  "title": "Cognito User Pool uses insecure advanced security additional flow",
  "short_description": "The ALLOW_CUSTOM_AUTH flow can bypass built-in risk detection and should not be enabled.",
  "severity": "MEDIUM",
  "type": "VIOLATION",
  "categories": ["authentication"],
  "recommended_action": "Remove ALLOW_CUSTOM_AUTH from user_pool_add_ons.advanced_security_additional_flows."
}

violation[res] {
  rc := input.resource_changes[_]
  rc.type == "aws_cognitoidp_user_pool"
  after := rc.change.after
  flows := after.user_pool_add_ons.advanced_security_additional_flows
  some i
  flows[i] == "ALLOW_CUSTOM_AUTH"
  res := {
    "msg": sprintf("Resource '%s' has insecure flow 'ALLOW_CUSTOM_AUTH' in advanced_security_additional_flows", [rc.address]),
    "resource": rc.address
  }
}