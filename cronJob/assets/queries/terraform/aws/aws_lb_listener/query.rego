package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

lb := {"aws_alb_listener", "aws_lb_listener"}

# Existing HTTP listener checks omitted for brevity...

# New rule: missing ssl_policy
CxPolicy[result] {
    resource := input.document[i].resource[lb[idx]][name]
    # only application load balancer listeners
    lbs := {"aws_alb", "aws_lb"}
    lb_info := split(resource.load_balancer_arn, ".")
    lb_name = lb_info[1]
    alb := input.document[_].resource[lbs[idx]][lb_name]
    (alb.load_balancer_type == "application"  or not common_lib.valid_key(alb, "load_balancer_type"))
    not common_lib.valid_key(resource, "ssl_policy")
    result := {
        "documentId": input.document[i].id,
        "resourceType": lb[idx],
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("%s[%s].ssl_policy", [lb[idx], name]),
        "searchLine": common_lib.build_search_line(["resource", lb[idx], name, "ssl_policy"], []),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "'ssl_policy' should be set to 'ELBSecurityPolicy-TLS-1-2-2017-01' or higher",
        "keyActualValue": "'ssl_policy' is missing",
        "remediation": "ssl_policy = \"ELBSecurityPolicy-TLS-1-2-2017-01\"",
        "remediationType": "addition"
    }
}

# New rule: incorrect ssl_policy value
CxPolicy[result] {
    resource := input.document[i].resource[lb[idx]][name]
    # only application load balancer listeners
    lbs := {"aws_alb", "aws_lb"}
    lb_info := split(resource.load_balancer_arn, ".")
    lb_name = lb_info[1]
    alb := input.document[_].resource[lbs[idx]][lb_name]
    (alb.load_balancer_type == "application"  or not common_lib.valid_key(alb, "load_balancer_type"))
    common_lib.valid_key(resource, "ssl_policy")
    resource.ssl_policy != "ELBSecurityPolicy-TLS-1-2-2017-01"
    result := {
        "documentId": input.document[i].id,
        "resourceType": lb[idx],
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("%s[%s].ssl_policy", [lb[idx], name]),
        "searchLine": common_lib.build_search_line(["resource", lb[idx], name, "ssl_policy"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "'ssl_policy' should be 'ELBSecurityPolicy-TLS-1-2-2017-01' or higher",
        "keyActualValue": sprintf("'ssl_policy' is equal '%s'", [resource.ssl_policy]),
        "remediation": json.marshal({"before": sprintf("%s", [resource.ssl_policy]), "after": "ELBSecurityPolicy-TLS-1-2-2017-01"}),
        "remediationType": "replacement"
    }
}