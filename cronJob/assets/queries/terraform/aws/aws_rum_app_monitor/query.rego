package terraform.aws_rum

import data.terraform.nodes as tf

violation[{{"msg": msg, "resource": rs}}] {
  rs := tf.resource[kind][name]
  kind == "aws_rum_app_monitor"
  not rs.config.domain_list
  msg := sprintf("Resource '%s' of type '%s' should specify 'domain_list' to restrict allowed domains.", [name, kind])
}
