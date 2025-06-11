package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Ensure HTTPS listeners specify a secure ssl_policy
CxPolicy[result] {
  resource := input.document[i].resource["aws_lb_listener"][name]
  upper(resource.protocol) == "HTTPS"
  # Missing ssl_policy attribute
  not common_lib.valid_key(resource, "ssl_policy")

  result := {
    "documentId": input.document[i].id,
    "resourceType": "aws_lb_listener",
    "resourceName": tf_lib.get_resource_name(resource, name),
    "searchKey": sprintf("aws_lb_listener[%s].ssl_policy", [name]),
    "searchLine": common_lib.build_search_line(["resource","aws_lb_listener",name,"ssl_policy"], []),
    "issueType": "MissingAttribute",
    "keyExpectedValue": "'ssl_policy' should be specified with a strong TLS 1.2+ policy",
    "keyActualValue": "'ssl_policy' is missing",
    "remediation": "ssl_policy = \"ELBSecurityPolicy-FS-1-2-Res-2020-10\"",
    "remediationType": "addition"
  }
}