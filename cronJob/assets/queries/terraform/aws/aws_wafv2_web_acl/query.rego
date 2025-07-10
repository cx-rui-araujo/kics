package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Updated rule to detect when an AWS API Gateway Stage is not protected by WAF
# and when the referenced AWS WAFv2 Web ACL is missing data_protection_config
CxPolicy[result] {
    # Find API Gateway Stage
    apiGateway := input.document[i].resource.aws_api_gateway_stage[stageName]

    # Check that it has no WAF association OR the associated Web ACL lacks data_protection_config
    not has_waf_associated(stageName, aclName) 

    # Retrieve the referenced Web ACL resource if it exists
    webACL := input.document[_].resource.aws_wafv2_web_acl[aclName]

    # Ensure data_protection_config is present
    not webACL.data_protection_config

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_api_gateway_stage & aws_wafv2_web_acl",
        "resourceName": tf_lib.get_resource_name(apiGateway, stageName),
        "searchKey": sprintf("aws_api_gateway_stage[%s] & aws_wafv2_web_acl[%s]", [stageName, aclName]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "API Gateway Stage should be associated with a WAF and the Web ACL must define data_protection_config",
        "keyActualValue": "Missing WAF association or data_protection_config",
        "searchLine": common_lib.build_search_line(["resource", "aws_api_gateway_stage", stageName], []),
    }
}

has_waf_associated(apiGatewayName, aclName) {
    # Possible association resources
    assocTypes := {"aws_wafregional_web_acl_association", "aws_wafv2_web_acl_association"}
    assoc := assocTypes[_]
    assocRes := input.document[_].resource[assoc][_]

    # Parse ARN to extract stage name and ACL name
    parts := split(assocRes.resource_arn, ".")
    parts[0] == "${aws_api_gateway_stage"
    parts[1] == apiGatewayName
    # Extract the referenced ACL resource name from association
    split(assocRes.web_acl_arn, "/")[1] == aclName
}