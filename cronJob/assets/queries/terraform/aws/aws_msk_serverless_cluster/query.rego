package terraform.msk
__rego_metadata__ := {"id":"KICS-EXAMPLE-1","title":"Detect MSK Serverless SASL IAM bootstrap brokers enabled","severity":"MEDIUM","category":"Misconfiguration"}

deny[msg] {
  input.resource_changes[_] == rc
  rc.type == "aws_msk_serverless_cluster"
  rc.change.after.bootstrap_brokers_sasl_iam == true
  msg := sprintf("Cluster '%s' has SASL IAM bootstrap brokers enabled. Ensure only trusted principals have kafka:GetBootstrapBrokers permission.", [rc.change.after.cluster_name])
}