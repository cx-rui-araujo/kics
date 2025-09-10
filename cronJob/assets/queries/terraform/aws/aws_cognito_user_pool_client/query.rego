package tfsec

__rego_metadata__ := {\n    \"id\": \"AWS009\",\n    \"title\": \"Ensure AWS Cognito User Pool Client refresh_token_rotation is enabled\",\n    \"severity\": \"MEDIUM\",\n    \"type\": \"VIOLATION::SECURITY\"\n}\n\nviolation[resource] {\n    resource := config.resource.aws_cognito_user_pool_client[_]\n    refresh := resource.config.refresh_token_rotation\n    refresh != true\n}