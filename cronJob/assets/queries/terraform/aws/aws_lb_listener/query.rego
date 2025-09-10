package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

lb := {"aws_alb_listener", "aws_lb_listener"}

# New rule: ensure explicit secure SSL policy to avoid default insecure policy
CxPolicy[result] {
  resource := input.document[i].resource[lb[idx]][name]
  # only application listeners on HTTPS
  common_lib.valid_key(resource, "protocol")
  upper(resource.protocol) == "HTTPS"

  # ssl_policy must be set and must enforce TLS1.2+
  not common_lib.valid_key(resource, "ssl_policy")

  result := {
    "documentId": input.document[i].id,
    "resourceType": lb[idx],
    "resourceName": tf_lib.get_resource_name(resource, name),
    "searchKey": sprintf("%s[%s].ssl_policy", [lb[idx], name]),
    "searchLine": common_lib.build_search_line(["resource", lb[idx], name, "ssl_policy"], []),
    "issueType": "MissingAttribute",
    "keyExpectedValue": "'ssl_policy' should be set to a TLS1.2-only policy",
    "keyActualValue": "'ssl_policy' is missing",
    "remediation": "ssl_policy = \"ELBSecurityPolicy-TLS-1-2-2017-01\"",
    "remediationType": "addition",
  }
}