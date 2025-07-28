package main

import data.terraform as tf

# 1. Missing user_identity_type allows unauthenticated access
violation[{
    "msg": msg,
    "resource": res.Address
}] {
    res := tf.plan.resource_changes[_]
    res.Type == "aws_workspaces_directory"
    not res.Change.After.user_identity_type
    msg = "Resource is missing 'user_identity_type', which may allow unauthenticated access."
}

# 2. Insecure active_directory_config with open DNS
violation[{
    "msg": msg,
    "resource": res.Address
}] {
    res := tf.plan.resource_changes[_]
    res.Type == "aws_workspaces_directory"
    ad := res.Change.After.active_directory_config
    ad != null
    insecure := ad.dns_ip_addresses[_] == "0.0.0.0/0"
    insecure
    msg = "'active_directory_config' has 0.0.0.0/0 which is an insecure DNS configuration."
}

# 3. Empty or public workspace_directory_description may expose intent
violation[{
    "msg": msg,
    "resource": res.Address
}] {
    res := tf.plan.resource_changes[_]
    res.Type == "aws_workspaces_directory"
    desc := res.Change.After.workspace_directory_description
    desc == ""
    msg = "Empty 'workspace_directory_description' may hide misconfiguration."
}

# 4. Default workspace_directory_name exposes enumeration risk
violation[{
    "msg": msg,
    "resource": res.Address
}] {
    res := tf.plan.resource_changes[_]
    res.Type == "aws_workspaces_directory"
    name := res.Change.After.workspace_directory_name
    name == "default"
    msg = "Using default 'workspace_directory_name' exposes predictable naming for enumeration."
}

# 5. AUTO_STOP workspace_type may result in data retention gaps
violation[{
    "msg": msg,
    "resource": res.Address
}] {
    res := tf.plan.resource_changes[_]
    res.Type == "aws_workspaces_directory"
    type := res.Change.After.workspace_type
    type == "AUTO_STOP"
    msg = "'workspace_type' set to 'AUTO_STOP' may lead to unexpected data loss."
}