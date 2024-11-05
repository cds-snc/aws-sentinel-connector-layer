resource "aws_iam_role" "lambda_list_layers" {
  name               = "lambda-list-layers"
  assume_role_policy = sensitive(data.aws_iam_policy_document.lambda_list_layers_assume.json)
}

resource "aws_iam_policy" "lambda_list_layers" {
  name        = "lambda-list-layers"
  description = "Policy to allow listing Lambda layers and versions"
  policy      = data.aws_iam_policy_document.lambda_list_layers.json
}

resource "aws_iam_role_policy_attachment" "lambda_list_layers" {
  role       = aws_iam_role.lambda_list_layers.name
  policy_arn = aws_iam_policy.lambda_list_layers.arn
}

data "aws_iam_policy_document" "lambda_list_layers_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type = "AWS"
      identifiers = concat(
        var.lambda_list_layers_assume_principals,
        [
          "arn:aws:iam::239043911459:role/notification-terraform-apply",
          "arn:aws:iam::239043911459:role/notification-terraform-plan",
          "arn:aws:iam::296255494825:role/notification-terraform-apply",
          "arn:aws:iam::296255494825:role/notification-terraform-plan",
          "arn:aws:iam::800095993820:role/notification-terraform-apply",
          "arn:aws:iam::800095993820:role/notification-terraform-plan",
        ]
      )
    }
  }
}

data "aws_iam_policy_document" "lambda_list_layers" {
  statement {
    sid    = "ListLayers"
    effect = "Allow"
    actions = [
      "lambda:ListLayers",
      "lambda:ListLayerVersions"
    ]
    resources = ["*"]
  }
}
