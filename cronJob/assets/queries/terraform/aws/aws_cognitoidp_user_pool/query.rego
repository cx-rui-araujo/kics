package kics

violation[{
  "msg": msg,
  "metadata": {"resource": resource.name}
}] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognitoidp_user_pool"
  after := resource.change.after
  addons := after.user_pool_add_ons
  flows := addons.advanced_security_additional_flows
  flows[_] == "ADMIN_NO_SRP_AUTH"
  msg := sprintf(
    "Resource '%s' enables ADMIN_NO_SRP_AUTH flow in advanced_security_additional_flows, which may bypass secure SRP authentication.",
    [resource.name]
  )
}