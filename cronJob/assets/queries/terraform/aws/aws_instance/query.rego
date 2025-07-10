package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
    resource := input.document[i].resource.aws_instance[name]
    common_lib.valid_key(resource, "network_interface")
    some ni_idx
    network_interface := resource.network_interface[ni_idx]
    not common_lib.valid_key(network_interface, "associate_public_ip_address")
    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_instance",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_instance[%s].network_interface[%d].associate_public_ip_address", [name, ni_idx]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "'network_interface[*].associate_public_ip_address' should be defined and not null",
        "keyActualValue": "'network_interface[*].associate_public_ip_address' is undefined or null",
        "remediation": "associate_public_ip_address = false",
        "remediationType": "addition",
    }
}