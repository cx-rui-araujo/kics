package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Detect aws_wafv2_web_acl resources without a data_protection_config block
CxPolicy[result] {
    webacl := input.document[i].resource.aws_wafv2_web_acl[name]
    not webacl.data_protection_config

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_wafv2_web_acl",
        "resourceName": tf_lib.get_resource_name(webacl, name),
        "searchKey": sprintf("aws_wafv2_web_acl[%s]", [name]),
        "issueType": "MissingDataProtectionConfig",
        "keyExpectedValue": "data_protection_config must be specified to redact sensitive data.",
        "keyActualValue": "data_protection_config block is missing.",
        "searchLine": common_lib.build_search_line(["resource", "aws_wafv2_web_acl", name], []),
    }
}