package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
  waf_acl := input.document[i].resource.aws_wafv2_web_acl[name]
  not waf_acl.data_protection_config

  result := {
    "documentId": input.document[i].id,
    "resourceType": "aws_wafv2_web_acl",
    "resourceName": tf_lib.get_resource_name(waf_acl, name),
    "searchKey": sprintf("aws_wafv2_web_acl[%s]", [name]),
    "issueType": "MissingDataProtectionConfig",
    "keyExpectedValue": "aws_wafv2_web_acl should define data_protection_config to protect sensitive data",
    "keyActualValue": "data_protection_config is not defined",
    "searchLine": common_lib.build_search_line(["resource","aws_wafv2_web_acl", name], [])
  }
}