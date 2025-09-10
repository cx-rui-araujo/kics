package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# rule for missing data_protection_config
CxPolicy[result] {
  tf := input.document[i].resource.aws_wafv2_web_acl[name]
  not tf.data_protection_config
  result := {
    "documentId": input.document[i].id,
    "resourceType": "aws_wafv2_web_acl",
    "resourceName": tf_lib.get_resource_name(tf, name),
    "searchKey": sprintf("aws_wafv2_web_acl[%s]", [name]),
    "issueType": "MissingField",
    "keyExpectedValue": "data_protection_config block should be defined",
    "keyActualValue": "data_protection_config block is missing",
    "searchLine": common_lib.build_search_line(["resource", "aws_wafv2_web_acl", name], []),
  }
}

# rule for missing uri_fragment in field_to_match
CxPolicy[result] {
  tf := input.document[i].resource.aws_wafv2_web_acl[name]
  some ruleIndex
  ruleItem := tf.rule[ruleIndex]
  statement := ruleItem.statement[_]
  match := statement.field_to_match
  not match.uri_fragment
  result := {
    "documentId": input.document[i].id,
    "resourceType": "aws_wafv2_web_acl",
    "resourceName": tf_lib.get_resource_name(tf, name),
    "searchKey": sprintf("aws_wafv2_web_acl[%s].rule[%d]", [name, ruleIndex]),
    "issueType": "MissingField",
    "keyExpectedValue": "field_to_match block should include uri_fragment",
    "keyActualValue": "uri_fragment is missing from field_to_match",
    "searchLine": common_lib.build_search_line(["resource", "aws_wafv2_web_acl", name, "rule", ruleIndex], []),
  }
}