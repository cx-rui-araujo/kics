package terraform_security

import data.terraform.plan.resource_changes

__rego_metadata__ := {
  "id": "AWS008",
  "version": "1.0.0",
  "title": "Ensure Cognito User Pool does not allow insecure advanced security flows",
  "description": "Checks that advanced_security_additional_flows does not include insecure flows such as ALLOW_USER_PASSWORD_AUTH",
  "severity": "MEDIUM",
  "type": "VIOLATION",
  "platform": "Terraform",
  "categories": ["Security"]
}

violation[{
  "resource": rc.address,
  "message": msg
}] {
  rc := resource_changes[_]
  rc.type == "aws_cognitoidp_user_pool"
  after := rc.change.after
  flows := after.user_pool_add_ons.advanced_security_additional_flows
  flows[_] == "ALLOW_USER_PASSWORD_AUTH"
  msg := sprintf("Insecure advanced security flow ALLOW_USER_PASSWORD_AUTH set in %s", [rc.address])
}