package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib
import json

# Updated rule to detect unintended source_dest_check behavior on network interfaces
CxPolicy[result] {
    resource := input.document[i].resource.aws_instance[name]
    some idx
    iface := resource.network_interface[idx]
    # missing or undefined source_dest_check
    not common_lib.valid_key(iface, "source_dest_check")
    result := {"documentId": input.document[i].id, "resourceType": "aws_instance", "resourceName": tf_lib.get_resource_name(resource, name), "searchKey": sprintf("aws_instance[%s].network_interface[%d]", [name, idx]), "issueType": "MissingAttribute", "keyExpectedValue": "'source_dest_check' should be set to false", "keyActualValue": "'source_dest_check' is undefined or null", "remediation": "source_dest_check = false", "remediationType": "addition"}
}

CxPolicy[result] {
    resource := input.document[i].resource.aws_instance[name]
    some idx
    iface := resource.network_interface[idx]
    # incorrect value: true
    iface.source_dest_check == true
    result := {"documentId": input.document[i].id, "resourceType": "aws_instance", "resourceName": tf_lib.get_resource_name(resource, name), "searchKey": sprintf("aws_instance[%s].network_interface[%d].source_dest_check", [name, idx]), "issueType": "IncorrectValue", "keyExpectedValue": "'source_dest_check' should be set to false", "keyActualValue": sprintf("'source_dest_check' is set to '%v'", [iface.source_dest_check]), "remediation": json.marshal({"before": iface.source_dest_check, "after": "false"}), "remediationType": "replacement"}
}