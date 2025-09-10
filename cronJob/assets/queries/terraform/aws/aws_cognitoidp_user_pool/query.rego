id: AWS042
metadata:
  name: 'Ensure AWS Cognito User Pool does not enable advanced security additional flows'
  description: 'Enabling user_pool_add_ons.advanced_security_additional_flows may weaken default MFA requirements by allowing additional risk-based authentication paths.'
  severity: MEDIUM
  recommended_actions: 'Remove or disable the advanced_security_additional_flows argument to maintain a stricter authentication posture.'
  link: 'https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-security.html'
  categories: ['security','aws','cognito']
  scope: terraform
  engine: rego
  engine_options:
    version: '0.1'
    query: |
      package main

      __rego_metadata__ := {
        'id': 'AWS042',
        'title': 'Ensure AWS Cognito User Pool does not enable advanced security additional flows',
        'severity': 'MEDIUM',
        'type': 'KICS',
        'category': 'Security',
        'description': 'Enabling advanced_security_additional_flows for aws_cognitoidp_user_pool can allow risk-based authentication flows that inadvertently weaken MFA requirements.'
      }

      violation[resource] {
        resource := input.resource_changes[_]
        resource.type == 'aws_cognitoidp_user_pool'
        after := resource.change.after
        after.user_pool_add_ons.advanced_security_additional_flows
      }