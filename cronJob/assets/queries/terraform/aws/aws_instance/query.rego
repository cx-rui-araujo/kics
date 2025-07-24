package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Detect aws_instance resources using network_interface attachments without explicit security_groups
CxPolicy[result] {
    resource := input.document[i].resource.aws_instance[name]
    # Instance defines a network_interface block
    common_lib.valid_key(resource, "network_interface")
    # Iterate each network interface attachment
    iface := resource.network_interface[_]
    # Ensure no security_groups are specified on the interface
    not common_lib.valid_key(iface, "security_groups")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_instance",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_instance[%s].network_interface", [name]),
        "searchLine": common_lib.build_search_line(["resource", "aws_instance", name, "network_interface"], []),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "Each network_interface block should define security_groups",
        "keyActualValue": "network_interface block is missing security_groups",
        "remediation": "Add `security_groups = [aws_security_group.example.id]` inside network_interface",
        "remediationType": "addition",
    }
}