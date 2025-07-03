package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Existing checks for associate_public_ip_address when no network_interface
CxPolicy[result] {
    resource := input.document[i].resource.aws_instance[name]

    not common_lib.valid_key(resource, "associate_public_ip_address")
    not common_lib.valid_key(resource, "network_interface")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_instance",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_instance[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "'associate_public_ip_address' should be defined and not null",
        "keyActualValue": "'associate_public_ip_address' is undefined or null",
        "searchLine": common_lib.build_search_line(["resource", "aws_instance", name], []),
    }
}

# Existing module checks omitted for brevity...
# Existing incorrect-value check when no network_interface
CxPolicy[result] {
    resource := input.document[i].resource.aws_instance[name]

    isTrue(resource.associate_public_ip_address)
    not common_lib.valid_key(resource, "network_interface")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_instance",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_instance[%s].associate_public_ip_address", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "'associate_public_ip_address' should be set to false",
        "keyActualValue": "'associate_public_ip_address' is true",
        "searchLine": common_lib.build_search_line(["resource", "aws_instance", name, "associate_public_ip_address"], []),
    }
}

# New check: network_interface blocks must not enable public IP
CxPolicy[result] {
    resource := input.document[i].resource.aws_instance[name]
    idx := index
    networkInterface := resource.network_interface[idx]

    common_lib.valid_key(networkInterface, "associate_public_ip_address")
    isTrue(networkInterface.associate_public_ip_address)

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_instance",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_instance[%s].network_interface[%d].associate_public_ip_address", [name, idx]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "'associate_public_ip_address' within network_interface should be set to false",
        "keyActualValue": "'associate_public_ip_address' is true",
        "searchLine": common_lib.build_search_line(["resource", "aws_instance", name, "network_interface", tostring(idx), "associate_public_ip_address"], []),
    }
}

isTrue(answer) {
    lower(answer) == "yes"
} else {
    lower(answer) == "true"
} else {
    answer == true
}