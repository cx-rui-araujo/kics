id: 'AWS1000'
title: 'Avoid usage of ssm_parameter_configuration in aws_imagebuilder_distribution_configuration'
description: 'The use of ssm_parameter_configuration in AWS EC2 Image Builder distribution configuration can overwrite existing SSM parameters, leading to potential unauthorized AMI deployments.'
severity: 'MEDIUM'
categories:
  - 'vulnerability'
  - 'iam'
scope:
  - 'terraform'
platform:
  - 'aws'
metadata:
  recommended_actions:
    - 'Remove the ssm_parameter_configuration block or validate the parameter name and access permissions'
queries:
  - query:
      language: 'rego'
      source: |
        package kics

        import input

        violation[res] {
          resource := input.resource_changes[_]
          resource.type == "aws_imagebuilder_distribution_configuration"
          after := resource.change.after
          after.distribution.ssm_parameter_configuration
          res := {
            "msg": "Avoid using ssm_parameter_configuration in aws_imagebuilder_distribution_configuration to prevent overwriting SSM parameters",
            "resource": resource.address
          }
        }
    metadata:
      id: 'AWS1000'
      name: 'imagebuilder-ssm-parameter-overwrite'
      service: 'EC2 Image Builder'
      short_description: 'Detect usage of ssm_parameter_configuration in imagebuilder distribution configuration'
      severity: 'MEDIUM'
      recommended_actions:
        - 'Remove or restrict ssm_parameter_configuration blocks'
relevant:
  - 'resource_changes'
  - 'change.after.distribution.ssm_parameter_configuration'