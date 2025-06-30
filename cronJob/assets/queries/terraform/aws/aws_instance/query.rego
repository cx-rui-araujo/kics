package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Existing checks for associate_public_ip_address on aws_instance
CxPolicy[result] {
    resource := input.document[i].resource.aws_instance[name]

    not common_lib.valid_key(resource, "associate_public_ip_address")
    not common_lib.valid_key(resource, "network_interface")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_instance",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_instance.%s", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "'associate_public_ip_address' should be defined and not null",
        "keyActualValue": "'associate_public_ip_address' is undefined or null",
        "searchLine": common_lib.build_search_line(["resource", "aws_instance", name], []),
    }
}

CxPolicy[result] {
    module := input.document[i].module[name]
    keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_instance", "associate_public_ip_address")
    netInterfaceKey := common_lib.get_module_equivalent_key("aws", module.source, "aws_instance", "network_interface")

    not common_lib.valid_key(module, netInterfaceKey)
    not common_lib.valid_key(module, keyToCheck)

    result := {
        "documentId": input.document[i].id,
        "resourceType": "n/a",
        "resourceName": "n/a",
        "searchKey": sprintf("module[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "'associate_public_ip_address' should be defined and not null",
        "keyActualValue": "'associate_public_ip_address' is undefined or null",
        "searchLine": common_lib.build_search_line(["module", name], []),
    }
}

CxPolicy[result] {
    resource := input.document[i].resource.aws_instance[name]

    isTrue(resource.associate_public_ip_address)
    not common_lib.valid_key(resource, "network_interface")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_instance",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_instance.%s.associate_public_ip_address", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "'associate_public_ip_address' should be set to false",
        "keyActualValue": "'associate_public_ip_address' is true",
        "searchLine": common_lib.build_search_line(["resource", "aws_instance", name, "associate_public_ip_address"], []),
    }
}

CxPolicy[result] {
    module := input.document[i].module[name]
    keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_instance", "associate_public_ip_address")
    netInterfaceKey := common_lib.get_module_equivalent_key("aws", module.source, "aws_instance", "network_interface")

    not common_lib.valid_key(module, netInterfaceKey)
    isTrue(module[keyToCheck])

    result := {
        "documentId": input.document[i].id,
        "resourceType": "n/a",
        "resourceName": "n/a",
        "searchKey": sprintf("module[%s].associate_public_ip_address", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "'associate_public_ip_address' should be set to false",
        "keyActualValue": "'associate_public_ip_address' is true",
        "searchLine": common_lib.build_search_line(["module", name, "associate_public_ip_address"], []),
    }
}

# New checks for network_interface blocks in aws_instance
CxPolicy[result] {
    resource := input.document[i].resource.aws_instance[name]
    networkInterface := resource.network_interface[_]

    not common_lib.valid_key(networkInterface, "associate_public_ip_address")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_instance",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_instance[%s].network_interface", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "'associate_public_ip_address' should be defined and not null in network_interface block",
        "keyActualValue": "'associate_public_ip_address' is undefined or null",
        "searchLine": common_lib.build_search_line(["resource", "aws_instance", name, "network_interface"], []),
    }
}

CxPolicy[result] {
    resource := input.document[i].resource.aws_instance[name]
    networkInterface := resource.network_interface[_]

    common_lib.valid_key(networkInterface, "associate_public_ip_address")
    isTrue(networkInterface.associate_public_ip_address)

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_instance",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_instance[%s].network_interface.associate_public_ip_address", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "'associate_public_ip_address' should be set to false in network_interface block",
        "keyActualValue": "'associate_public_ip_address' is true",
        "searchLine": common_lib.build_search_line(["resource", "aws_instance", name, "network_interface", "associate_public_ip_address"], []),
    }
}

# helper for truthy values
isTrue(answer) {
    lower(answer) == "yes"
} else {
    lower(answer) == "true"
} else {
    answer == true
}