package tfcloudwatchevent

violation[{"msg": msg, "resource": r.address}] {
  r := input.modules[_].resources[_]
  r.type == "aws_cloudwatch_event_connection"
  r.values.kms_key_identifier
  keyid := r.values.kms_key_identifier
  k := input.modules[_].resources[_]
  k.type == "aws_kms_key"
  k.values.key_id == keyid
  not k.values.enable_key_rotation
  msg := sprintf("KMS key %v used by CloudWatch Event connection does not have key rotation enabled.",[keyid])
}