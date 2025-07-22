package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
    webacl := input.document[i].resource.aws_wafv2_web_acl[name]
    rule := webacl.rule[_]
    stmt := rule.statement[_]
    field := stmt.field_to_match

    not field.uri_fragment

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_wafv2_web_acl",
        "resourceName": tf_lib.get_resource_name(webacl, name),
        "searchKey": sprintf("aws_wafv2_web_acl[%s]", [name]),
        "issueType": "MissingUriFragmentMatch",
        "keyExpectedValue": "WAF Web ACL should inspect the URI fragment via field_to_match.uri_fragment",
        "keyActualValue": sprintf("WAF Web ACL rule '%s' does not include 'uri_fragment' in field_to_match", [rule.name]),
        "searchLine": common_lib.build_search_line(["resource", "aws_wafv2_web_acl", name, "rule", rule.name, "statement", "field_to_match"], []),
    }
}