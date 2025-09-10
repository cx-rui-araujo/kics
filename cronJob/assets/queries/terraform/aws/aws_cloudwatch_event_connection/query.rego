package main

import data.tfconfig

vulnerabilities[res] {
  block := data.tfconfig.blocks[_]
  block.type == "resource"
  block.labels[0] == "aws_cloudwatch_event_connection"
  not block.body.kms_key_identifier
  res := {
    "resource_name": block.labels[1],
    "rule_id": "KICS-AWS-EventConnection-Unencrypted",
    "message": "aws_cloudwatch_event_connection is missing kms_key_identifier: sensitive data will not be encrypted",
    "severity": "HIGH"
  }
}