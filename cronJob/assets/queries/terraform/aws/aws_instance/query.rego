package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Existing public-IP checks omitted for brevity

# New rule: detect aws_instance.network_interface without associate_public_ip_address
CxPolicy[result] {
	doc := input.document[i]
	resource := doc.resource.aws_instance[name]

	# For each network_interface block
	net := resource.network_interface[_]
	# Missing associate_public_ip_address leads to default true
	not common_lib.valid_key(net, "associate_public_ip_address")

	result := {
		"documentId": doc.id,
		"resourceType": "aws_instance",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_instance[%s].network_interface", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "'associate_public_ip_address' should be defined in network_interface and set to false",
		"keyActualValue": "'network_interface.associate_public_ip_address' is undefined or null",
		"searchLine": common_lib.build_search_line(["resource", "aws_instance", name, "network_interface"], []),
	}
}

# New rule: detect network_interface associate_public_ip_address set to true
CxPolicy[result] {
	doc := input.document[i]
	resource := doc.resource.aws_instance[name]

	net := resource.network_interface[_]
	# Explicitly true is insecure
	isTrue(net.associate_public_ip_address)

	result := {
		"documentId": doc.id,
		"resourceType": "aws_instance",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_instance[%s].network_interface.associate_public_ip_address", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'associate_public_ip_address' in network_interface should be set to false",
		"keyActualValue": "'network_interface.associate_public_ip_address' is true",
		"searchLine": common_lib.build_search_line(["resource", "aws_instance", name, "network_interface", "associate_public_ip_address"], []),
	}
}

# helper for boolean check
isTrue(answer) {
	lower(answer) == "true"
} else {
	answer == true
}