output "api_endpoint" {
  value = var.domain_name == null ? aws_cloudformation_stack.thin_egress_app.outputs.ApiEndpoint : "https://${var.domain_name}/"
}

output "rest_api" {
  value = {
    id               = aws_cloudformation_stack.thin_egress_app.outputs.RestApiId,
    root_resource_id = aws_cloudformation_stack.thin_egress_app.outputs.RestApiRootResourceId
  }
}

output "rest_api_stage_name" {
  value = aws_cloudformation_stack.thin_egress_app.outputs.RestApiDeploymentStage
}

output "urs_redirect_uri" {
  value = var.domain_name == null ? aws_cloudformation_stack.thin_egress_app.outputs.URSredirectURI : "https://${var.domain_name}/login"
}
