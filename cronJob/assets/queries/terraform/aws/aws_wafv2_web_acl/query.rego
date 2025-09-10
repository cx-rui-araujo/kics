package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
    apiGateway := input.document[i].resource.aws_api_gateway_stage[name]
    not has_waf_with_data_protection(apiGateway, name)

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_api_gateway_stage",
        "resourceName": tf_lib.get_resource_name(apiGateway, name),
        "searchKey": sprintf("aws_api_gateway_stage[%s]", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "Associated WAF must have data_protection_config defined",
        "keyActualValue": "Associated WAF missing data_protection_config",
        "searchLine": common_lib.build_search_line(["resource", "aws_api_gateway_stage", name], [])
    }
}

has_waf_with_data_protection(apiGateway, apiGatewayName) {
    # find association to a WAF
    resType := {"aws_wafregional_web_acl_association", "aws_wafv2_web_acl_association"}[_]
    assoc := input.document[_].resource[resType][_]
    parts := split(assoc.resource_arn, ".")
    parts[0] == "aws_api_gateway_stage"
    parts[1] == apiGatewayName

    # find the attached WAFv2 WebACL
    webAclArn := assoc.web_acl_arn
    webAcl := input.document[_].resource.aws_wafv2_web_acl[_]
    webAcl.arn == webAclArn

    # ensure data_protection_config block is present
    count(webAcl.data_protection_config) > 0
}