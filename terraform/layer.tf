resource "aws_lambda_layer_version" "lambda_layer" {
  filename   = "layer.zip"
  layer_name = "aws-sentinel-connector-layer"

  source_code_hash = filebase64sha256("layer.zip")

  compatible_runtimes = ["python3.9"]
}