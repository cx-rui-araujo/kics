package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
    acl := input.document[i].resource.aws_wafv2_web_acl[name]
    not has_uri_fragment(acl)

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_wafv2_web_acl",
        "resourceName": tf_lib.get_resource_name(acl, name),
        "searchKey": sprintf("aws_wafv2_web_acl[%s]", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "WAFv2 Web ACL should include URI fragment in field_to_match",
        "keyActualValue": "WAFv2 Web ACL field_to_match is missing uri_fragment",
        "searchLine": common_lib.build_search_line(["resource", "aws_wafv2_web_acl", name], []),
    }
}

has_uri_fragment(acl) {
    some r
    rule := acl.rule[r]
    # Check XSS match statements; extend for other statement types as needed
    stmt := rule.statement.xss_match_statement
    field := stmt.field_to_match[_]
    field.uri_fragment
}