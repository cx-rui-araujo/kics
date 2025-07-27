package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
    acl := input.document[i].resource.aws_wafv2_web_acl[name]
    missing_data_protection_config(acl)
    missing_uri_fragment(acl)

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_wafv2_web_acl",
        "resourceName": tf_lib.get_resource_name(acl, name),
        "searchKey": sprintf("aws_wafv2_web_acl[%s]", [name]),
        "issueType": "MissingConfiguration",
        "keyExpectedValue": "WAF ACL should configure data_protection_config and include uri_fragment in field_to_match",
        "keyActualValue": sprintf("data_protection_config present: %v, uri_fragment present: %v", [not missing_data_protection_config(acl), not missing_uri_fragment(acl)]),
        "searchLine": common_lib.build_search_line(["resource", "aws_wafv2_web_acl", name], []),
    }
}

missing_data_protection_config(acl) {
    not acl.data_protection_config
}

missing_uri_fragment(acl) {
    some i
    acl.rule[i].statement.byte_match_statement
    not acl.rule[i].statement.byte_match_statement.field_to_match.uri_fragment
}