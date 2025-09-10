package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

lb := {"aws_alb_listener", "aws_lb_listener"}

# Existing checks for HTTP listeners omitted for brevity...

# New check: Ensure TLS listeners explicitly set a secure ssl_policy
CxPolicy[result] {
    resource := input.document[i].resource["aws_lb_listener"][name]
    # Only HTTPS listeners
    upper(resource.protocol) == "HTTPS"
    # ssl_policy must be provided
    not common_lib.valid_key(resource, "ssl_policy")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_lb_listener",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_lb_listener[%s].ssl_policy", [name]),
        "searchLine": common_lib.build_search_line(["resource", "aws_lb_listener", name, "ssl_policy"], []),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "'ssl_policy' should be explicitly set to a secure policy (e.g., ELBSecurityPolicy-TLS-1-2-2017-01)",
        "keyActualValue": "'ssl_policy' is missing",
        "remediation": "ssl_policy = \"ELBSecurityPolicy-TLS-1-2-2017-01\"",
        "remediationType": "addition",
    }
}