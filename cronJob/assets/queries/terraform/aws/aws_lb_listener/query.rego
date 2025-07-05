package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Detect missing ssl_policy on HTTPS/TLS ALB listeners due to default-zero omission (#41846)
CxPolicy[result] {
  resource := input.document[i].resource.aws_lb_listener[name]

  # Only for secure protocols
  upper(resource.protocol) == "HTTPS"

  # ssl_policy must be explicitly set; absence may fall back to insecure defaults
  not common_lib.valid_key(resource, "ssl_policy")

  result := {
    "documentId": input.document[i].id,
    "resourceType": "aws_lb_listener",
    "resourceName": tf_lib.get_resource_name(resource, name),
    "searchKey": sprintf("aws_lb_listener[%s]", [name]),
    "searchLine": common_lib.build_search_line(["resource", "aws_lb_listener", name], []),
    "issueType": "MissingAttribute",
    "keyExpectedValue": "'ssl_policy' should be defined for HTTPS listeners",
    "keyActualValue": "'ssl_policy' is missing",
    "remediation": "ssl_policy = \"ELBSecurityPolicy-2016-08\"",
    "remediationType": "addition"
  }
}