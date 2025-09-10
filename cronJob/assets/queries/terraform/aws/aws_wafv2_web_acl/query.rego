package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
  webacl := input.document[i].resource.aws_wafv2_web_acl[name]
  not has_data_protection_config(webacl)
  result := {
    "documentId": input.document[i].id,
    "resourceType": "aws_wafv2_web_acl",
    "resourceName": tf_lib.get_resource_name(webacl, name),
    "searchKey": sprintf("aws_wafv2_web_acl[%s]", [name]),
    "issueType": "MissingValue",
    "keyExpectedValue": "data_protection_config block with at least one data_exfiltration_blocking_configuration",
    "keyActualValue": "no data_protection_config block configured",
    "searchLine": common_lib.build_search_line(["resource", "aws_wafv2_web_acl", name], []),
  }
}

has_data_protection_config(r) {
  r.data_protection_config
}