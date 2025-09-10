package main
import tfconfig

deny[res] {
  resource := tfconfig.resources.aws_rum_app_monitor[_]
  # If neither domain nor a non-empty domain_list is set, the monitor can collect data from any origin
  not resource.values.domain
  (not resource.values.domain_list) or count(resource.values.domain_list) == 0
  res := {"message": "aws_rum_app_monitor should specify domain or domain_list to restrict monitored domains","resource": resource.address}
}