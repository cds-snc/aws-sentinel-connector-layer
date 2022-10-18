resource "aws_ecrpublic_repository" "aws-sentinel-connector-layer" {
  provider = aws.us-east-1

  repository_name = "aws-sentinel-connector"

  catalog_data {
    description = "repo for the aws-sentinel-connector artifact"
  }

  tags = {
    CostCentre = var.billing_code
    Terraform  = true
  }
}