package main

__rego_metadata__ := {
  "id": "AWS.IBDC.SSMNoKMS",
  "title": "Ensure Image Builder distribution SSM parameters are encrypted with KMS",
  "severity": "HIGH",
  "type": "VULNERABILITY",
  "match_spec": {
    "vendors": ["aws"],
    "types": ["aws_imagebuilder_distribution_configuration" ]
  }
}

deny[msg] {
  dist := input.distribution[_]
  ssm := dist.ssm_parameter_configuration[_]
  ssm.parameter_type == "String"
  not ssm.kms_key_id
  msg := sprintf("Resource '%s' defines SSM parameter '%s' without KMS encryption", [input.resource_name, ssm.parameter_name])
}