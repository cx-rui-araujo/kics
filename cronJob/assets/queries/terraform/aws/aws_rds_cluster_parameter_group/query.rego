package terraform.aws.RDSClusterParameterGroup

# Deny when collation_server is not valid for the given character_set
violation[{
    "msg": msg,
    "resource": resource
}] {
    resource := input.resource
    resource.Type == "aws_rds_cluster_parameter_group"

    # find the collation_server parameter
    collParam := resource.Values.parameter[_]
    collParam.name == "collation_server"
    collValue := collParam.value

    # find the character_set parameter
    charParam := resource.Values.parameter[_]
    charParam.name == "character_set"
    charValue := charParam.value

    # lookup a map of valid collations for each character_set (external data)
    validCollations := data.valid_rds_collations[charValue]

    # if the chosen collation is not in the list of valid collations, flag it
    not collValue == validCollations[_]

    msg := sprintf("Invalid collation_server '%s' for character_set '%s'", [collValue, charValue])
}