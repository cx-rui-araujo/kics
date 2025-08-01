package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
    acl := input.document[i].resource.aws_wafv2_web_acl[name]
    rule := acl.rule[_]
    rule.statement.byte_match_statement.field_to_match.uri_fragment

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_wafv2_web_acl",
        "resourceName": tf_lib.get_resource_name(acl, name),
        "searchKey": sprintf("aws_wafv2_web_acl[%s]", [name]),
        "issueType": "Misconfiguration",
        "keyExpectedValue": "Do not use uri_fragment in field_to_match as fragments are not sent to the WAF",
        "keyActualValue": "uri_fragment found in field_to_match",
        "searchLine": common_lib.build_search_line(["resource", "aws_wafv2_web_acl", name], [])
    }
}