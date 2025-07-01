package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Updated to catch public IP assignment in network_interface blocks
CxPolicy[result] {
    resource := input.document[i].resource.aws_instance[name]
    common_lib.valid_key(resource, "network_interface")
    some idx
    iface := resource.network_interface[idx]
    isTrue(iface.associate_public_ip_address)
    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_instance",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_instance[%s].network_interface[%d].associate_public_ip_address", [name, idx]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "'associate_public_ip_address' should be set to false",
        "keyActualValue": "'associate_public_ip_address' is true",
        "searchLine": common_lib.build_search_line(["resource", "aws_instance", name, "network_interface", "associate_public_ip_address"], []),
    }
}

# preserve existing truthiness helper
isTrue(answer) {
    lower(answer) == "yes"
} else {
    lower(answer) == "true"
} else {
    answer == true
}