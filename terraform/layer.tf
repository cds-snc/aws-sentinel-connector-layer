resource "aws_lambda_layer_version" "lambda_layer" {
  filename   = "layer.zip"
  layer_name = "aws-sentinel-connector-layer"

  source_code_hash = filebase64sha256("layer.zip")

  # One entry, because the artifact genuinely supports one runtime: the wheels
  # are built for a single CPython ABI (PYTHON_VERSION in ../layer/Makefile) and
  # cpython-3XX extensions are not importable on any other version.
  #
  # This list used to name python3.10 through 3.14 while the zip contained
  # cpython-312 extensions, so four of the five were false and the one consumer
  # that attached it — on python3.13, which the sentinel_forwarder module
  # hard-codes — failed on every invocation. Keep this in step with
  # PYTHON_VERSION; the build's verify-abi target enforces the other half.
  compatible_runtimes = [
    "python3.13"
  ]

  skip_destroy = true
}

# This resource is bound to the version this apply publishes, so each publish
# replaces it — and the destroy half silently removed the share from the
# previous version. Consumers already running an older version kept working,
# because lambda:GetLayerVersion is checked when a layer is attached rather
# than at invoke time, so nothing surfaced until a consumer tried to move to a
# version that was no longer the newest. It then failed its apply with a bare
# AccessDeniedException naming no cause (ai-answers, layer 270, after 271
# shipped).
#
# skip_destroy keeps the permission on every version the layer retains, which
# matches skip_destroy on the version itself: versions are kept, so their
# shares have to be kept too.
resource "aws_lambda_layer_version_permission" "lambda_layer_permission" {
  layer_name     = aws_lambda_layer_version.lambda_layer.layer_arn
  version_number = aws_lambda_layer_version.lambda_layer.version
  principal      = "*"
  action         = "lambda:GetLayerVersion"
  statement_id   = "shared-layer-permission"

  skip_destroy = true
}

# The same artifact, published in us-east-1 for forwarders that must run there.
# A Lambda can only attach a layer from its own region, and WAF logs for
# CloudFront land in us-east-1, so a CloudFront WAF forwarder cannot use the
# ca-central-1 layer. Version numbers are counted per region, so this layer's
# versions do not match the ca-central-1 ones.
resource "aws_lambda_layer_version" "lambda_layer_us_east_1" {
  provider = aws.us-east-1

  filename   = "layer.zip"
  layer_name = "aws-sentinel-connector-layer"

  source_code_hash = filebase64sha256("layer.zip")

  # Keep in step with lambda_layer above.
  compatible_runtimes = [
    "python3.13"
  ]

  skip_destroy = true
}

resource "aws_lambda_layer_version_permission" "lambda_layer_permission_us_east_1" {
  provider = aws.us-east-1

  layer_name     = aws_lambda_layer_version.lambda_layer_us_east_1.layer_arn
  version_number = aws_lambda_layer_version.lambda_layer_us_east_1.version
  principal      = "*"
  action         = "lambda:GetLayerVersion"
  statement_id   = "shared-layer-permission"

  skip_destroy = true
}
