package main

violation[resource] {
  resource := data.resource.aws_cognitoidp_user_pool[_]
  addons := resource.values.user_pool_add_ons[0]
  flows := addons.advanced_security_additional_flows
  flow := flows[_]
  insecure[flow]
}

insecure = {"USER_PASSWORD_AUTH", "ADMIN_USER_PASSWORD_AUTH"}
