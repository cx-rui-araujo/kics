package aws

__rego_metadata__ = {
  "id": "AWS_RUM_APP_MONITOR_01",
  "title": "Ensure aws_rum_app_monitor domain_list does not allow wildcards and domain is set",
  "severity": "MEDIUM",
  "type": "misconfiguration",
  "supported_languages": ["terraform"],
  "categories": ["security"]
}

__rego_doc__ = "Detects if aws_rum_app_monitor resource has wildcard entries in domain_list or is missing the domain attribute which may lead to data exfiltration or unexpected behavior."

violation[res] {
  resource := tfconfig.resources[type][name]
  type == "aws_rum_app_monitor"
  (
    any_wildcard(resource.values.domain_list)
    or
    not resource.values.domain
  )
  res = {
    "resource": name,
    "type": type,
  }
}

any_wildcard(list) {
  some i
  domain := list[i]
  startswith(domain, "*")
}
