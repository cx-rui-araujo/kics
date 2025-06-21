CxPolicy[result] {
    resource := input.document[i].resource[lb[idx]][name]

    check_application(resource)
    resource.protocol == "HTTPS"
    not common_lib.valid_key(resource, "ssl_policy")

    result := {
        "documentId": input.document[i].id,
        "resourceType": lb[idx],
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("%s[%s].ssl_policy", [lb[idx], name]),
        "searchLine": common_lib.build_search_line(["resource", lb[idx], name, "ssl_policy"], []),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "'ssl_policy' should be specified to enforce a secure TLS policy",
        "keyActualValue": "'ssl_policy' is missing",
        "remediation": "ssl_policy = \"ELBSecurityPolicy-FS-1-2-Res-2020-10\"",
        "remediationType": "addition",
    }
}