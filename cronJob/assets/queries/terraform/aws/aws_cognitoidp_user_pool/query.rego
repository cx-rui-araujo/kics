package main

__rego_meta__ := {
  "id": "KICS-AWS-0001",
  "title": "Ensure no insecure additional flows in AWS Cognito user pool",
  "severity": "HIGH",
  "type": "VULNERABILITY",
  "description": "The advanced_security_additional_flows argument should not include insecure authentication flows that bypass SRP or admin checks.",
  "recommended_actions": "Remove insecure additional flows like ADMIN_USER_PASSWORD_AUTH from advanced_security_additional_flows."
}

violation[res] {
  input.resource.type == "aws_cognitoidp_user_pool"
  addon := input.resource.values.user_pool_add_ons
  flows := addon.advanced_security_additional_flows
  insecure := {"ALLOW_ADMIN_USER_PASSWORD_AUTH","ALLOW_CUSTOM_AUTH","ALLOW_USER_PASSWORD_AUTH"}
  flow := flows[_]
  insecure[flow]
  res := {
    "resource_id": input.resource.id,
    "message": sprintf("Insecure additional flow '%s' found in advanced_security_additional_flows", [flow])
  }
}