variable "billing_code" {
  description = "The billing code to tag our resources with"
  type        = string
}

variable "lambda_list_layers_assume_principals" {
  description = "The list of AWS principals role ARNs that can assume the lambda-list-layers role"
  type        = list(string)
  sensitive   = true
}