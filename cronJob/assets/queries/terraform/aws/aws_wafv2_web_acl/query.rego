package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
    webACL := input.document[i].resource.aws_wafv2_web_acl[name]
    not webACL.data_protection_config
    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_wafv2_web_acl",
        "resourceName": tf_lib.get_resource_name(webACL, name),
        "searchKey": sprintf("aws_wafv2_web_acl[%s]", [name]),
        "issueType": "MissingDataProtectionConfig",
        "keyExpectedValue": "aws_wafv2_web_acl should include data_protection_config to mask sensitive data",
        "keyActualValue": "data_protection_config is not set",
        "searchLine": common_lib.build_search_line(["resource", "aws_wafv2_web_acl", name], []),
    }
}