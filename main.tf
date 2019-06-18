locals {
  create_download_role = var.download_role_arn == ""
  db_sess              = var.session_store == "DB"
  s3_sess              = var.session_store == "S3"
}

data "aws_caller_identity" "current" {}

# Egress Lambda IAM role

data "aws_iam_policy_document" "assume_lambda_role" {
  statement {
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "egress_lambda_iam_role" {
  name                 = "${var.prefix}-EgressLambdaIamRole"
  assume_role_policy   = "${data.aws_iam_policy_document.assume_lambda_role.json}"
  permissions_boundary = var.permissions_boundary
}

data "aws_iam_policy_document" "egress_lambda_role_policy_document" {
  statement {
    actions = [
      "sts:AssumeRole",
      "secretsmanager:GetSecretValue"
    ]
    resources = ["*"]
  }
  statement {
    actions = [
      "s3:GetObject",
      "s3:ListBucket"
    ]
    resources = [
      "arn:aws:s3:::${var.config_bucket}",
      "arn:aws:s3:::${var.config_bucket}/*"
    ]
  }
  statement {
    actions   = ["lambda:InvokeFunction"]
    resources = ["*"]
  }
  statement {
    actions = [
      "ec2:CreateNetworkInterface",
      "ec2:DeleteNetworkInterface",
      "ec2:DescribeNetworkInterfaces"
    ]
    resources = ["*"]
  }
  statement {
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["arn:aws:logs:*:*:*"]
  }
}

resource "aws_iam_role_policy" "egress_lambda_role_policy" {
  name   = "${var.prefix}-IamPolicy"
  role   = "${aws_iam_role.egress_lambda_iam_role.id}"
  policy = "${data.aws_iam_policy_document.egress_lambda_role_policy_document.json}"
}

# Session info stored in DynamoDB

resource "aws_dynamodb_table" "egress_session_table" {
  count        = local.db_sess ? 1 : 0
  name         = "${var.prefix}-egress-session-table"
  billing_mode = "PAY_PER_REQUEST"

  hash_key = "id"

  attribute {
    name = "id"
    type = "S"
  }

  ttl {
    attribute_name = "expires"
    enabled        = true
  }
}

data "aws_iam_policy_document" "egress_lambda_session_db_policy_document" {
  statement {
    actions = [
      "dynamodb:BatchGetItem",
      "dynamodb:DeleteItem",
      "dynamodb:DescribeLimits",
      "dynamodb:DescribeReservedCapacity",
      "dynamodb:DescribeTable",
      "dynamodb:GetItem",
      "dynamodb:ListTagsOfResource",
      "dynamodb:PutItem",
      "dynamodb:Query",
      "dynamodb:UpdateItem"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "egress_lambda_session_db_policy" {
  count  = local.db_sess ? 1 : 0
  name   = "${var.prefix}-EgressLambdaIamPolicyDb"
  role   = "${aws_iam_role.egress_lambda_iam_role.id}"
  policy = "${data.aws_iam_policy_document.egress_lambda_session_db_policy_document.json}"
}

# Session info stored in S3

resource "aws_s3_bucket" "egress_lambda_session_s3" {
  count  = local.s3_sess ? 1 : 0
  bucket = "${var.prefix}-sessions"
  lifecycle_rule {
    enabled = true
    expiration {
      days = 30
    }
  }
}

data "aws_iam_policy_document" "egress_lambda_session_s3_policy_document" {
  statement {
    actions   = ["s3:*"]
    resources = local.s3_sess ? ["${aws_s3_bucket.egress_lambda_session_s3[0].arn}/*"] : []
  }
}

resource "aws_iam_role_policy" "egress_lambda_session_s3_policy" {
  count  = local.s3_sess ? 1 : 0
  name   = "${var.prefix}-EgressLambdaIamPolicyS3"
  role   = "${aws_iam_role.egress_lambda_iam_role.id}"
  policy = "${data.aws_iam_policy_document.egress_lambda_session_s3_policy_document.json}"
}

# Download IAM role

data "aws_iam_policy_document" "assume_aws_iam_role" {
  statement {
    principals {
      type = "AWS"
      identifiers = [
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      ]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "download_local_iam_role" {
  count                = local.create_download_role ? 1 : 0
  name                 = "${var.prefix}-DownloadRoleLocal"
  assume_role_policy   = "${data.aws_iam_policy_document.assume_aws_iam_role.json}"
  permissions_boundary = var.permissions_boundary
}

data "aws_iam_policy_document" "download_role_policy_document" {
  statement {
    actions = [
      "s3:GetObject",
      "s3:ListBucket",
      "s3:GetBucketLocation"
    ]
    resources = flatten([
      [for x in var.buckets : "arn:aws:s3:::${x}"],
      [for x in var.buckets : "arn:aws:s3:::${x}/*"]
    ])
  }
}

resource "aws_iam_role_policy" "download_role_policy" {
  count  = local.create_download_role ? 1 : 0
  name   = "${var.prefix}-IamPolicy"
  role   = aws_iam_role.download_local_iam_role[0].id
  policy = data.aws_iam_policy_document.download_role_policy_document.json
}

# Egress Lambda function

resource "aws_security_group" "egress_lambda_sg" {
  count  = length(var.subnet_ids) > 0 ? 1 : 0
  vpc_id = var.vpc_id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_lambda_function" "egress_lambda" {
  function_name = "${var.prefix}-EgressLambda"
  runtime       = "python3.7"
  handler       = "app.app"
  role          = "${aws_iam_role.egress_lambda_iam_role.arn}"
  timeout       = 6
  # publish = true
  s3_bucket = var.lambda_code_s3_bucket
  s3_key    = var.lambda_code_s3_key == "" ? "thin-egress-app/tea-code-${var.build_id}.zip" : var.lambda_code_s3_key

  vpc_config {
    security_group_ids = [aws_security_group.egress_lambda_sg[0].id]
    subnet_ids         = var.subnet_ids
  }

  environment {
    variables = {
      AUTH_BASE_URL                = var.auth_base_url
      BUCKET_MAP_FILE              = var.bucket_map_file
      BUCKETNAME_PREFIX            = var.bucketname_prefix
      BUILD_VERSION                = var.build_id
      CONFIG_BUCKET                = var.config_bucket
      DOMAIN_NAME                  = var.domain_name
      EGRESS_APP_DOWNLOAD_ROLE_ARN = local.create_download_role ? aws_iam_role.download_local_iam_role[0].arn : var.download_role_arn
      HTML_TEMPLATE_DIR            = var.html_template_dir
      LOGLEVEL                     = var.log_level
      MATURITY                     = var.maturity
      PRIVATE_BUCKETS_FILE         = var.private_buckets_file
      PUBLIC_BUCKETS_FILE          = var.public_buckets_file
      S3_SIGNATURE_VERSION         = "s3v4"
      SESSION_BUCKET               = local.s3_sess ? aws_s3_bucket.egress_lambda_session_s3[0].bucket : null
      SESSION_STORE                = var.session_store
      SESSION_TABLE                = local.db_sess ? aws_dynamodb_table.egress_session_table[0].id : null
      SESSION_TTL_HRS              = var.session_ttl_hrs
      STAGE_NAME                   = var.stage_name
      URS_CREDS_SECRET_NAME        = var.urs_creds_secret_name
      USE_REVERSE_BUCKET_MAP       = var.use_reverse_bucket_map
    }
  }
}

# Egress API Gateway

data "aws_iam_policy_document" "egress_gateway_rest_api_policy" {
  statement {
    actions   = ["*"]
    resources = ["*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

resource "aws_api_gateway_rest_api" "egress_gateway" {
  name = "${var.prefix}-EgressGateway"

  endpoint_configuration {
    types = [var.use_private_vpc ? "PRIVATE" : "EDGE"]
  }

  policy = var.use_private_vpc ? data.aws_iam_policy_document.egress_gateway_rest_api_policy.json : null
}


resource "aws_lambda_permission" "lambda_permission" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.egress_lambda.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.egress_gateway.execution_arn}/*"
}

# GET /

resource "aws_api_gateway_method" "egress_api_root_method" {
  rest_api_id   = aws_api_gateway_rest_api.egress_gateway.id
  resource_id   = aws_api_gateway_rest_api.egress_gateway.root_resource_id
  http_method   = "GET"
  authorization = "NONE"
  request_parameters = {
    "method.request.header.Cookie" = true
  }
}

resource "aws_api_gateway_integration" "egress_gateway_root_integration" {
  rest_api_id             = aws_api_gateway_rest_api.egress_gateway.id
  resource_id             = aws_api_gateway_rest_api.egress_gateway.root_resource_id
  http_method             = aws_api_gateway_method.egress_api_root_method.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.egress_lambda.invoke_arn
}

resource "aws_api_gateway_method_response" "egress_gateway_root_integration_200_response" {
  rest_api_id = aws_api_gateway_rest_api.egress_gateway.id
  resource_id = aws_api_gateway_rest_api.egress_gateway.root_resource_id
  http_method = aws_api_gateway_method.egress_api_root_method.http_method
  status_code = "200"
  response_parameters = {
    "method.response.header.Set-Cookie" = true
  }
}

# GET /login

resource "aws_api_gateway_resource" "egress_gateway_login_resource" {
  rest_api_id = aws_api_gateway_rest_api.egress_gateway.id
  parent_id   = aws_api_gateway_rest_api.egress_gateway.root_resource_id
  path_part   = "login"
}

resource "aws_api_gateway_method" "egress_api_login_method" {
  rest_api_id   = aws_api_gateway_rest_api.egress_gateway.id
  resource_id   = aws_api_gateway_resource.egress_gateway_login_resource.id
  http_method   = "GET"
  authorization = "NONE"
  request_parameters = {
    "method.request.header.Cookie" = true
  }
}

resource "aws_api_gateway_integration" "egress_gateway_login_integration" {
  rest_api_id             = aws_api_gateway_rest_api.egress_gateway.id
  resource_id             = aws_api_gateway_resource.egress_gateway_login_resource.id
  http_method             = aws_api_gateway_method.egress_api_login_method.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.egress_lambda.invoke_arn
}

resource "aws_api_gateway_method_response" "egress_gateway_login_integration_200_response" {
  rest_api_id = aws_api_gateway_rest_api.egress_gateway.id
  resource_id = aws_api_gateway_resource.egress_gateway_login_resource.id
  http_method = aws_api_gateway_method.egress_api_login_method.http_method
  status_code = "200"
  response_parameters = {
    "method.response.header.Set-Cookie" = true
  }
}

resource "aws_api_gateway_method_response" "egress_gateway_login_integration_301_response" {
  rest_api_id = aws_api_gateway_rest_api.egress_gateway.id
  resource_id = aws_api_gateway_resource.egress_gateway_login_resource.id
  http_method = aws_api_gateway_method.egress_api_login_method.http_method
  status_code = "301"
  response_parameters = {
    "method.response.header.Location"   = true
    "method.response.header.Set-Cookie" = true
  }
}

# GET /logout

resource "aws_api_gateway_resource" "egress_gateway_logout_resource" {
  rest_api_id = aws_api_gateway_rest_api.egress_gateway.id
  parent_id   = aws_api_gateway_rest_api.egress_gateway.root_resource_id
  path_part   = "logout"
}

resource "aws_api_gateway_method" "egress_api_logout_method" {
  rest_api_id   = aws_api_gateway_rest_api.egress_gateway.id
  resource_id   = aws_api_gateway_resource.egress_gateway_logout_resource.id
  http_method   = "GET"
  authorization = "NONE"
  request_parameters = {
    "method.request.header.Cookie" = true
  }
}

resource "aws_api_gateway_integration" "egress_gateway_logout_integration" {
  rest_api_id             = aws_api_gateway_rest_api.egress_gateway.id
  resource_id             = aws_api_gateway_resource.egress_gateway_logout_resource.id
  http_method             = aws_api_gateway_method.egress_api_logout_method.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.egress_lambda.invoke_arn
}

resource "aws_api_gateway_method_response" "egress_gateway_logout_integration_200_response" {
  rest_api_id = aws_api_gateway_rest_api.egress_gateway.id
  resource_id = aws_api_gateway_resource.egress_gateway_logout_resource.id
  http_method = aws_api_gateway_method.egress_api_logout_method.http_method
  status_code = "200"
  response_parameters = {
    "method.response.header.Set-Cookie" = true
  }
}

resource "aws_api_gateway_method_response" "egress_gateway_logout_integration_301_response" {
  rest_api_id = aws_api_gateway_rest_api.egress_gateway.id
  resource_id = aws_api_gateway_resource.egress_gateway_logout_resource.id
  http_method = aws_api_gateway_method.egress_api_logout_method.http_method
  status_code = "301"
  response_parameters = {
    "method.response.header.Set-Cookie" = true
  }
}

# GET /profile

resource "aws_api_gateway_resource" "egress_gateway_profile_resource" {
  rest_api_id = aws_api_gateway_rest_api.egress_gateway.id
  parent_id   = aws_api_gateway_rest_api.egress_gateway.root_resource_id
  path_part   = "profile"
}

resource "aws_api_gateway_method" "egress_api_profile_method" {
  rest_api_id   = aws_api_gateway_rest_api.egress_gateway.id
  resource_id   = aws_api_gateway_resource.egress_gateway_profile_resource.id
  http_method   = "GET"
  authorization = "NONE"
  request_parameters = {
    "method.request.header.Cookie"             = true,
    "method.request.header.X-urs-access-token" = true
  }
}

resource "aws_api_gateway_integration" "egress_gateway_profile_integration" {
  rest_api_id             = aws_api_gateway_rest_api.egress_gateway.id
  resource_id             = aws_api_gateway_resource.egress_gateway_profile_resource.id
  http_method             = aws_api_gateway_method.egress_api_profile_method.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.egress_lambda.invoke_arn
}

# ANY /{proxy+}

resource "aws_api_gateway_resource" "egress_gateway_dynamic_resource" {
  rest_api_id = aws_api_gateway_rest_api.egress_gateway.id
  parent_id   = aws_api_gateway_rest_api.egress_gateway.root_resource_id
  path_part   = "{proxy+}"
}

resource "aws_api_gateway_integration" "egress_gateway_dynamic_integration" {
  rest_api_id             = aws_api_gateway_rest_api.egress_gateway.id
  resource_id             = aws_api_gateway_resource.egress_gateway_dynamic_resource.id
  http_method             = aws_api_gateway_method.egress_api_dynamic_method.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.egress_lambda.invoke_arn
}

resource "aws_api_gateway_method" "egress_api_dynamic_method" {
  rest_api_id   = aws_api_gateway_rest_api.egress_gateway.id
  resource_id   = aws_api_gateway_resource.egress_gateway_dynamic_resource.id
  http_method   = "ANY"
  authorization = "NONE"
  request_parameters = {
    "method.request.header.Cookie"             = true,
    "method.request.header.X-urs-access-token" = true
  }
}

resource "aws_api_gateway_method_response" "egress_gateway_dynamic_method_response_200" {
  rest_api_id = aws_api_gateway_rest_api.egress_gateway.id
  resource_id = aws_api_gateway_resource.egress_gateway_dynamic_resource.id
  http_method = aws_api_gateway_method.egress_api_dynamic_method.http_method
  status_code = "200"
  response_parameters = {
    "method.response.header.Accept-Ranges"  = true
    "method.response.header.Content-Length" = true
    "method.response.header.Content-Type"   = true
    "method.response.header.Date"           = true
    "method.response.header.ETag"           = true
    "method.response.header.Last-Modified"  = true
    "method.response.header.Set-Cookie"     = true
  }
}

resource "aws_api_gateway_method_response" "egress_gateway_dynamic_method_response_301" {
  rest_api_id = aws_api_gateway_rest_api.egress_gateway.id
  resource_id = aws_api_gateway_resource.egress_gateway_dynamic_resource.id
  http_method = aws_api_gateway_method.egress_api_dynamic_method.http_method
  status_code = "301"
  response_parameters = {
    "method.response.header.Accept-Ranges"  = true
    "method.response.header.Content-Length" = true
    "method.response.header.Content-Type"   = true
    "method.response.header.Date"           = true
    "method.response.header.ETag"           = true
    "method.response.header.Last-Modified"  = true
    "method.response.header.Location"       = true
    "method.response.header.Set-Cookie"     = true
  }
}

resource "aws_api_gateway_method_response" "egress_gateway_dynamic_method_response_303" {
  rest_api_id = aws_api_gateway_rest_api.egress_gateway.id
  resource_id = aws_api_gateway_resource.egress_gateway_dynamic_resource.id
  http_method = aws_api_gateway_method.egress_api_dynamic_method.http_method
  status_code = "303"
  response_parameters = {
    "method.response.header.Accept-Ranges"  = true
    "method.response.header.Content-Length" = true
    "method.response.header.Content-Type"   = true
    "method.response.header.Date"           = true
    "method.response.header.ETag"           = true
    "method.response.header.Last-Modified"  = true
    "method.response.header.Location"       = true
    "method.response.header.Set-Cookie"     = true
  }
}

# API Gateway deployment
resource "aws_api_gateway_deployment" "egress_api_deployment" {
  depends_on = [
    "aws_api_gateway_integration.egress_gateway_root_integration",
    "aws_api_gateway_integration.egress_gateway_login_integration",
    "aws_api_gateway_integration.egress_gateway_logout_integration",
    "aws_api_gateway_integration.egress_gateway_profile_integration",
    "aws_api_gateway_integration.egress_gateway_dynamic_integration"
  ]

  rest_api_id = aws_api_gateway_rest_api.egress_gateway.id
  stage_name  = var.stage_name
}
