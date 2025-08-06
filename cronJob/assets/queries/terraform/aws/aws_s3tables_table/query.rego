package terraform

import tfconfig "github.com/Checkmarx/kics/pkg/model/terraform"

violation[resource] {
  resource := tfconfig.Resource
  resource.Type == "aws_s3tables_table"
  # Encryption configuration must be defined to ensure data is encrypted at rest
  not resource.HasChild("encryption_configuration")
}