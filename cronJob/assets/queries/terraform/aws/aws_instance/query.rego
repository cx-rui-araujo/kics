package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# New check: catch network_interface blocks without explicit associate_public_ip_address
CxPolicy[result] {
    resource := input.document[i].resource.aws_instance[name]
    common_lib.valid_key(resource, "network_interface")
    # iterate over each network_interface block
    interface := resource.network_interface[_]
    # missing associate_public_ip_address in network_interface
    not common_lib.valid_key(interface, "associate_public_ip_address")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_instance",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_instance[%s].network_interface", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "'associate_public_ip_address' should be defined and not null in each network_interface block",
        "keyActualValue": "'associate_public_ip_address' is undefined or null in network_interface block",
        "searchLine": common_lib.build_search_line(["resource", "aws_instance", name, "network_interface"], []),
    }
}