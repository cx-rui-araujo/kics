package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Original checks for associate_public_ip_address when no network_interface is defined
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

# New checks to detect unintentional public IP assignment via network_interface block
CxPolicy[result] {
    resource := input.document[i].resource.aws_instance[name]
    netif := resource.network_interface[_]

    # no explicit associate_public_ip_address in the network_interface, default may assign a public IP
    not common_lib.valid_key(netif, "associate_public_ip_address")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_instance",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_instance[%s].network_interface[%d]", [name, _]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "'network_interface[].associate_public_ip_address' should be defined and set to false",
        "keyActualValue": sprintf("network_interface[%d] missing 'associate_public_ip_address'", [_]),
        "remediation": "associate_public_ip_address = false",
        "remediationType": "addition",
    }
}

CxPolicy[result] {
    resource := input.document[i].resource.aws_instance[name]
    netif := resource.network_interface[_]

    # explicit true assignment in network_interface is insecure
    isTrue(netif.associate_public_ip_address)

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_instance",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_instance[%s].network_interface[%d].associate_public_ip_address", [name, _]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "'network_interface[].associate_public_ip_address' should be set to false",
        "keyActualValue": sprintf("network_interface[%d].associate_public_ip_address is true", [_]),
        "searchLine": common_lib.build_search_line(["resource", "aws_instance", name, "network_interface", fmt.itoa(_), "associate_public_ip_address"], []),
        "remediation": json.marshal({"before":"true","after":"false"}),
        "remediationType": "replacement",
    }
}