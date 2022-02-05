resource "aws_lambda_layer_version" "lambda_layer" {
  filename   = "layer.zip"
  layer_name = "aws-sentinel-connector-layer"

  source_code_hash = filebase64sha256("layer.zip")

  compatible_runtimes = ["python3.9"]
}

resource "aws_lambda_layer_version_permission" "lambda_layer_permission" {
  layer_name     = aws_lambda_layer_version.lambda_layer.layer_name
  version_number = aws_lambda_layer_version.lambda_layer.version_number
  principal      = "*"
  action         = "lambda:GetLayerVersion"
  statement_id   = "shared-layer-permission"
}