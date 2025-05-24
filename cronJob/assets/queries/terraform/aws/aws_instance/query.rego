package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
    resource := input.document[i].resource.aws_instance[name]
    # Detect use of network_interface without specifying security_groups
    common_lib.valid_key(resource, "network_interface")
    ni := resource.network_interface[_]
    not common_lib.valid_key(ni, "security_groups")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_instance",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_instance[%s].network_interface", [name]),
        "searchLine": common_lib.build_search_line(["resource", "aws_instance", name, "network_interface"], []),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "'network_interface' block should define 'security_groups' to avoid default SG usage",
        "keyActualValue": "'network_interface' block missing 'security_groups'",
        "remediation": "specify security_groups or vpc_security_group_ids inside network_interface block",
        "remediationType": "addition",
    }
}