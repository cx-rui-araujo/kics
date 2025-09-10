package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Existing ALB Listening on HTTP rules omitted for brevity

# New rule: ensure HTTPS listeners explicitly set ssl_policy to avoid insecure defaults
CxPolicy[result] {
    resource := input.document[i].resource["aws_lb_listener"][name]
    # Only application load balancer listeners
    lbs := {"aws_alb", "aws_lb"}
    lb_info := split(resource.load_balancer_arn, ".")
    lb_name = lb_info[1]
    lb := input.document[_].resource[lbs[idx]][lb_name]
    (lb.load_balancer_type == "application" or not common_lib.valid_key(lb, "load_balancer_type"))

    # Listener is HTTPS
    common_lib.valid_key(resource, "protocol")
    upper(resource.protocol) == "HTTPS"

    # ssl_policy not set explicitly
    not common_lib.valid_key(resource, "ssl_policy")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_lb_listener",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_lb_listener[%s].ssl_policy", [name]),
        "searchLine": common_lib.build_search_line(["resource", "aws_lb_listener", name], []),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "'ssl_policy' should be explicitly set when protocol is HTTPS",
        "keyActualValue": "'ssl_policy' is missing",
        "remediation": "ssl_policy = \"ELBSecurityPolicy-2016-08\"",
        "remediationType": "addition",
    }
}