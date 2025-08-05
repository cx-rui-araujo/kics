package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Rule 1: Ensure WAFv2 Web ACL has data_protection_config to protect sensitive data
CxPolicy[res1] {
    webacl := input.document[i].resource.aws_wafv2_web_acl[name]
    not webacl.data_protection_config
    res1 := {
        "documentId": input.document[i].id,
        "resourceType": "aws_wafv2_web_acl",
        "resourceName": tf_lib.get_resource_name(webacl, name),
        "searchKey": sprintf("aws_wafv2_web_acl[%s]", [name]),
        "issueType": "MissingDataProtectionConfig",
        "keyExpectedValue": "data_protection_config should be configured",
        "keyActualValue": "data_protection_config is not configured",
        "searchLine": common_lib.build_search_line(["resource","aws_wafv2_web_acl",name], []),
    }
}

# Rule 2: Ensure byte_match_statement.field_to_match includes uri_fragment
CxPolicy[res2] {
    webacl := input.document[i].resource.aws_wafv2_web_acl[name]
    # iterate through all byte_match_statement blocks in any rule
    stmt := webacl.rule[_].statement.managed_rule_group_statement.scope_down_statement.byte_match_statement[_]
    not stmt.field_to_match.uri_fragment
    res2 := {
        "documentId": input.document[i].id,
        "resourceType": "aws_wafv2_web_acl",
        "resourceName": tf_lib.get_resource_name(webacl, name),
        "searchKey": sprintf("aws_wafv2_web_acl[%s] rule byte_match_statement", [name]),
        "issueType": "MissingURIFragmentMatch",
        "keyExpectedValue": "field_to_match must include uri_fragment",
        "keyActualValue": "uri_fragment not found in field_to_match",
        "searchLine": common_lib.build_search_line(["resource","aws_wafv2_web_acl",name], []),
    }
}