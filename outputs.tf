output "api_endpoint" {
  value = "${aws_api_gateway_deployment.egress_api_deployment.invoke_url}/"
}

output "urs_redirect_uri" {
  value = "${aws_api_gateway_deployment.egress_api_deployment.invoke_url}/${aws_api_gateway_resource.egress_gateway_login_resource.path_part}"
}
