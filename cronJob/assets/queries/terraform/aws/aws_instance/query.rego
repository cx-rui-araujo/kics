package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Original rule: missing associate_public_ip_address on aws_instance
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

# Original rule: module missing associate_public_ip_address
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

# Original rule: associate_public_ip_address true on aws_instance
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

# Original rule: module associate_public_ip_address true
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

# New rule: detect public IP assignment via network_interface block
CxPolicy[result] {
    resource := input.document[i].resource.aws_instance[name]
    common_lib.valid_key(resource, "network_interface")
    some j
    resource.network_interface[j].associate_public_ip_address == true

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_instance",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_instance[%s].network_interface[%d].associate_public_ip_address", [name, j]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "'associate_public_ip_address' in network_interface should be set to false",
        "keyActualValue": "'associate_public_ip_address' is true",
        "searchLine": common_lib.build_search_line(["resource", "aws_instance", name, "network_interface", sprintf("%d", [j]), "associate_public_ip_address"], []),
    }
}

# Helper to interpret boolean-like values
isTrue(answer) {
    lower(answer) == "yes"
} else {
    lower(answer) == "true"
} else {
    answer == true
}