package main

__rego_metadoc__ := {
    "id": "AWS070",
    "title": "Cognito Refresh Token Rotation should be enabled",
    "severity": "MEDIUM",
    "type": "Security Best Practices",
    "reference_id": "AWS.Cognito.UserPool.Client.1",
    "id_tags": ["terraform", "aws", "cognito", "refresh_token_rotation"]
}

violation[res] {
    input.Kind == "resource"
    input.Type == "aws_cognito_user_pool_client"
    attr := input.Values.refresh_token_rotation
    (attr == false) or not input.Values.refresh_token_rotation
    res := {
        "msg": sprintf("Resource '%s' has refresh_token_rotation disabled, which may lead to long-lived refresh tokens.", [input.Name]),
        "start_line": input.Range.Start,
        "end_line": input.Range.End,
    }
}