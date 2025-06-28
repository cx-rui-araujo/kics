package main

import data.terraform as tf

__rego_metadata__ := {
    "id": "AWS_WAFV2_URIFRAGMENT",
    "title": "WAFv2 rule group should not use field_to_match 'uri_fragment'",
    "severity": "MEDIUM",
    "type": "VULNERABILITY",
    "uri": "https://docs.aws.amazon.com/waf/latest/APIReference/API_FieldToMatch.html"
}

denies[violation] {
    resource := tf.resource.aws_wafv2_rule_group[_]
    rule := resource.rule[_]
    stmt := rule.statement.and_statement.statements[_]
    size := stmt.size_constraint_statement
    size.field_to_match.uri_fragment
    violation := {
        "resource": resource.address,
        "message": sprintf("Resource '%s' uses unsupported 'uri_fragment' in field_to_match", [resource.address])
    }
}