package main

__rego_metadoc__ := {"id":"KICS-999","version":"1.0","title":"Cognito advanced_security_additional_flows misuse","severity":"MEDIUM","type":"VULNERABILITY","category":"security","platform":"Terraform","description":"Enabling advanced_security_additional_flows may allow weaker authentication flows, reducing security posture."}

deny[response] {
  resource := terraform.resource_instances["aws_cognitoidp_user_pool"][_] 
  addons := resource.attributes.user_pool_add_ons
  flows := addons.advanced_security_additional_flows
  count(flows) > 0
  response := {
    "message": sprintf("Resource '%s' configures advanced_security_additional_flows (%v), which may weaken security.",[resource.address, flows]),
    "resource": resource.address
  }
}