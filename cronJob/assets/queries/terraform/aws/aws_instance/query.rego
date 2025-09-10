package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
    doc := input.document[i]
    resource := doc.resource.aws_instance[name]

    sgs := {"security_groups", "vpc_security_group_ids"}

    sgInfo := resource[sgs[s]][_]
    contains(lower(sgInfo), "default")

    result := {
        "documentId": doc.id,
        "resourceType": "aws_instance",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_instance[%s].%s", [name, sgs[s]]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("aws_instance[%s].%s should not be using default security group", [name, sgs[s]]),
        "keyActualValue": sprintf("aws_instance[%s].%s is using at least one default security group", [name, sgs[s]]),
        "searchLine": common_lib.build_search_line(["resource", "aws_instance", name, sgs[s]], []),
    }
}

// New checks for network_interface block
CxPolicy[result] {
    doc := input.document[i]
    resource := doc.resource.aws_instance[name]

    iface := resource.network_interface[_]
    sg := iface.security_groups[_]
    contains(lower(sg), "default")

    result := {
        "documentId": doc.id,
        "resourceType": "aws_instance",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_instance[%s].network_interface[].security_groups", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("aws_instance[%s].network_interface[].security_groups should not be using default security group", [name]),
        "keyActualValue": sprintf("aws_instance[%s].network_interface[].security_groups is using a default security group", [name]),
        "searchLine": common_lib.build_search_line(["resource", "aws_instance", name, "network_interface"], []),
    }
}

CxPolicy[result] {
    doc := input.document[i]
    resource := doc.resource.aws_instance[name]

    iface := resource.network_interface[_]
    sgid := iface.security_group_ids[_]
    contains(lower(sgid), "default")

    result := {
        "documentId": doc.id,
        "resourceType": "aws_instance",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_instance[%s].network_interface[].security_group_ids", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("aws_instance[%s].network_interface[].security_group_ids should not be using default security group", [name]),
        "keyActualValue": sprintf("aws_instance[%s].network_interface[].security_group_ids is using a default security group", [name]),
        "searchLine": common_lib.build_search_line(["resource", "aws_instance", name, "network_interface"], []),
    }
}