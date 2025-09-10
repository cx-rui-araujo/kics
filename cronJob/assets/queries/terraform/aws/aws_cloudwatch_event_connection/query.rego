---
id: AWSKMS01
title: "Ensure CloudWatch Event Connection uses validated KMS key"
severity: HIGH
categories: ["Encryption"]
description: "Ensure the kms_key_identifier is a valid KMS key ARN within the same AWS account to prevent external key usage"
query: |-
  package main

  __rego_metadata__ = {
      "id": "AWSKMS01",
      "title": "Ensure CloudWatch Event Connection uses validated KMS key",
      "severity": "HIGH",
      "type": "terraform_plan",
  }

  deny[msg] {
      rc := input.resource_changes[_]
      rc.type == "aws_cloudwatch_event_connection"
      kms := rc.change.after.kms_key_identifier
      kms
      not regex.match("^arn:aws:kms:[^:]+:[0-9]{12}:key/[0-9a-fA-F-]+$", [kms])
      msg := sprintf("Invalid KMS key ARN '%s' in resource '%s'", [kms, rc.address])
  }