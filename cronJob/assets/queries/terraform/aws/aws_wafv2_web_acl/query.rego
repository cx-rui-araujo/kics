package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
    waf := input.document[i].resource.aws_wafv2_web_acl[name]
    ruleBlock := waf.rule[idx]
    byteMatch := ruleBlock.statement.byte_match_statement
    byteMatch.field_to_match.uri_fragment
    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_wafv2_web_acl",
        "resourceName": tf_lib.get_resource_name(waf, name),
        "searchKey": sprintf("aws_wafv2_web_acl[%s].rule[%d].statement.byte_match_statement.field_to_match", [name, idx]),
        "issueType": "IneffectiveRule",
        "keyExpectedValue": "Avoid using uri_fragment in field_to_match for byte_match_statement",
        "keyActualValue": "uri_fragment is used in field_to_match",
        "searchLine": common_lib.build_search_line(["resource","aws_wafv2_web_acl",name,"rule",idx,"statement","byte_match_statement","field_to_match","uri_fragment"], []),
    }
}