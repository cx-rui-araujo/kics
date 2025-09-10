package kics

import data.tfplan

# Detect aws_controltower_control resources that lack proper ResourceNotFound exception handling on delete
# and may drop all custom parameters when removed
# Rule: flag any aws_controltower_control delete without explicit delete_handler or parameters block

rule MissingControlTowerDeleteHandling {
  resource := tfplan.resource_changes[_]
  resource.type == "aws_controltower_control"
  # if delete action is planned
  "delete" in resource.change.actions
  # and no custom delete handler defined
  not resource.change.after.arguments.delete_handler
}
