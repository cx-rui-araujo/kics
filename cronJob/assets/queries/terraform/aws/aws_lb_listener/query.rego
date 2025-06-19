package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

lb := {"aws_alb_listener", "aws_lb_listener"}

# New check: ensure explicit idle_timeout.timeout_seconds to avoid default excessive idle durations
CxPolicy[result] {
  resource := input.document[i].resource[lb[idx]][name]

  # Only application listeners
  check_application(resource)

  # idle_timeout.timeout_seconds must be explicitly set
  not common_lib.valid_key(resource.idle_timeout, "timeout_seconds")

  result := {
    "documentId": input.document[i].id,
    "resourceType": lb[idx],
    "resourceName": tf_lib.get_resource_name(resource, name),
    "searchKey": sprintf("%s[%s].idle_timeout.timeout_seconds", [lb[idx], name]),
    "searchLine": common_lib.build_search_line(["resource", lb[idx], name, "idle_timeout", "timeout_seconds"], []),
    "issueType": "MissingAttribute",
    "keyExpectedValue": "'idle_timeout.timeout_seconds' should be explicitly set to a safe value",
    "keyActualValue": "'idle_timeout.timeout_seconds' is missing",
    "remediation": "idle_timeout { timeout_seconds = 30 }",
    "remediationType": "addition",
  }
}

is_application(resource) {
  resource.load_balancer_type == "application"
}

is_application(resource) {
  not common_lib.valid_key(resource, "load_balancer_type")
}

check_application(resource) {
  lbs := {"aws_alb", "aws_lb"}
  lb_info := split(resource.load_balancer_arn, ".")
  lb_name = lb_info[1]
  lb := input.document[_].resource[lbs[idx]][name]
  lb_name == name
  is_application(lb)
}