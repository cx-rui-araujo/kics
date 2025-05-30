package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
    # Existing check: API Gateway Stage without any WAF associated
    apiGateway := input.document[i].resource.aws_api_gateway_stage[name]
    not has_waf_associated(name)
    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_api_gateway_stage",
        "resourceName": tf_lib.get_resource_name(apiGateway, name),
        "searchKey": sprintf("aws_api_gateway_stage[%s]", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "API Gateway Stage should be associated with a Web Application Firewall",
        "keyActualValue": "API Gateway Stage is not associated with a Web Application Firewall",
        "searchLine": common_lib.build_search_line(["resource", "aws_api_gateway_stage", name], []),
    }
}

CxPolicy[result] {
    # New check: WAF associated but missing data_protection_config on the Web ACL
    apiGateway := input.document[i].resource.aws_api_gateway_stage[name]
    has_waf_associated(name)
    not has_data_protection_config_for(name)
    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_api_gateway_stage",
        "resourceName": tf_lib.get_resource_name(apiGateway, name),
        "searchKey": sprintf("aws_api_gateway_stage[%s]", [name]),
        "issueType": "MissingDataProtectionConfig",
        "keyExpectedValue": "Associated WAF Web ACL should have data_protection_config enabled",
        "keyActualValue": "Associated WAF Web ACL missing data_protection_config",
        "searchLine": common_lib.build_search_line(["resource", "aws_api_gateway_stage", name], []),
    }
}

has_waf_associated(apiGatewayName) {
    targetResources := {"aws_wafregional_web_acl_association", "aws_wafv2_web_acl_association"}
    waf := targetResources[_]
    resource := input.document[_].resource[waf][_]
    associatedResource := split(resource.resource_arn, ".")
    associatedResource[0] == "${aws_api_gateway_stage"
    associatedResource[1] == apiGatewayName
}

has_data_protection_config_for(apiGatewayName) {
    # find the association linking this API Gateway to a WAFv2 Web ACL
    assoc := input.document[_].resource.aws_wafv2_web_acl_association[_]
    split(assoc.resource_arn, ".")[1] == apiGatewayName
    # lookup the referenced Web ACL by ARN and ensure data_protection_config is set
    some acl_name
    acl := input.document[_].resource.aws_wafv2_web_acl[acl_name]
    acl.data_protection_config
}