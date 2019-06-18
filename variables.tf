variable "auth_base_url" {
  type    = string
  default = "https://urs.earthdata.nasa.gov"
}

variable "bucketname_prefix" {
  type    = string
  default = ""
}

variable "buckets" {
  type    = list(string)
  default = []
}

variable "build_id" {
  type    = string
  default = "build.14"
}

variable "bucket_map_file" {
  type    = string
  default = "bucket_map.yaml"
}

variable "config_bucket" {
  type = string
}

variable "domain_name" {
  type    = string
  default = null
}

variable "download_role_arn" {
  type    = string
  default = ""
}

variable "html_template_dir" {
  type    = string
  default = ""
}

variable "lambda_code_s3_bucket" {
  type    = string
  default = "asf.public.code"
}

variable "lambda_code_s3_key" {
  type    = string
  default = ""
}

variable "log_level" {
  type    = string
  default = "DEBUG"
}

variable "maturity" {
  type    = string
  default = "DEV"
}

variable permissions_boundary {
  type    = string
  default = null
}

variable "prefix" {
  type = string
}

variable "private_buckets_file" {
  type    = string
  default = ""
}

variable "public_buckets_file" {
  type    = string
  default = ""
}

variable "session_store" {
  type    = string
  default = "DB"
}

variable "session_ttl_hrs" {
  type    = string
  default = "168"
}

variable "stage_name" {
  type    = string
  default = "DEV"
}

variable "subnet_ids" {
  type    = list(string)
  default = null
}

variable "urs_creds_secret_name" {
  type = string
}

variable "use_private_vpc" {
  type    = bool
  default = true
}

variable "use_reverse_bucket_map" {
  type    = string
  default = "False"
}

variable "vpc_id" {
  type = string
}
