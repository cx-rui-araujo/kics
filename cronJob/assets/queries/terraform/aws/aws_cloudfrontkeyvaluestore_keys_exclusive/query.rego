package main

__rego_metadata__ = {
  "id": "AWS999",
  "title": "Ensure CloudFront Key-Value Store enforces exclusive keys",
  "severity": "HIGH",
  "type": "AWS Terraform Security Check",
}

violation[{
  "msg": msg,
  "metadata": __rego_metadata__,
  "location": location,
}] {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudfrontkeyvaluestore_keys_exclusive"
  resource.change.after.exclusive == false
  location := resource.change.after
  msg := "CloudFront key-value store 'exclusive' flag is set to false, risk of key collision"
}