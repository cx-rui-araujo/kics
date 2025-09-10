package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Extend existing ALB listener checks to detect missing or default insecure SSL policies
lb := {"aws_alb_listener", "aws_lb_listener"}

# Detect listeners without an explicit ssl_policy (AWS will apply a default that may be insecure)
CxPolicy[result] {
  resource := input.document[i].resource[lb[idx]][name]
  # Only application listeners
  check_application(resource)
  # No ssl_policy set by user
  not common_lib.valid_key(resource, "ssl_policy")

  result := {
    "documentId": input.document[i].id,
    "resourceType": lb[idx],
    "resourceName": tf_lib.get_resource_name(resource, name),
    "searchKey": sprintf("%s[%s].ssl_policy", [lb[idx], name]),
    "searchLine": common_lib.build_search_line(["resource", lb[idx], name, "ssl_policy"], []),
    "issueType": "MissingAttribute",
    "keyExpectedValue": "'ssl_policy' should be specified to enforce TLS >= 1.2 (e.g. ELBSecurityPolicy-TLS-1-2-2017-01)",
    "keyActualValue": "'ssl_policy' is missing",
    "remediation": "ssl_policy = \"ELBSecurityPolicy-TLS-1-2-2017-01\"",
    "remediationType": "addition",
  }
}

# Detect listeners explicitly using an insecure or default SSL policy older than TLS 1.2
CxPolicy[result] {
  resource := input.document[i].resource[lb[idx]][name]
  check_application(resource)
  common_lib.valid_key(resource, "ssl_policy")
  # Match common insecure default policies or anything not containing TLS-1-2
  not contains(resource.ssl_policy, "TLS-1-2")

  result := {
    "documentId": input.document[i].id,
    "resourceType": lb[idx],
    "resourceName": tf_lib.get_resource_name(resource, name),
    "searchKey": sprintf("%s[%s].ssl_policy", [lb[idx], name]),
    "searchLine": common_lib.build_search_line(["resource", lb[idx], name, "ssl_policy"], []),
    "issueType": "IncorrectValue",
    "keyExpectedValue": "'ssl_policy' should enforce TLS >= 1.2",
    "keyActualValue": sprintf("'ssl_policy' is '%s'", [resource.ssl_policy]),
    "remediation": json.marshal({"before": resource.ssl_policy, "after": "ELBSecurityPolicy-TLS-1-2-2017-01"}),
    "remediationType": "replacement",
  }
}

# Reuse existing helper from original query
check_application(resource) {
  lbs := {"aws_alb", "aws_lb"}
  lb_info := split(resource.load_balancer_arn, ".")
  lb_name = lb_info[1]
  lb := input.document[_].resource[lbs[idx]][name]
  lb_name == name
  is_application(lb)
}

is_application(resource) {
  resource.load_balancer_type == "application"
}
is_application(resource) {
  not common_lib.valid_key(resource, "load_balancer_type")
}