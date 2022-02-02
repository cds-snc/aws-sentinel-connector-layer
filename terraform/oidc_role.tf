locals {
  admin_role = "AWSSentinelConnectorLayerTerraformAdministratorRole"
}

# Role used by Terraform to manage all satellite accounts
module "gh_oidc_roles" {
  source = "github.com/cds-snc/terraform-modules?ref=v1.0.3//gh_oidc_role"
  roles = [
    {
      name      = local.admin_role
      repo_name = "aws-sentinel-connector-layer"
      claim     = "ref:refs/heads/main"
    }
  ]

  billing_tag_value = var.billing_code
}

data "aws_iam_policy" "admin" {
  name = "AdministratorAccess"
}

resource "aws_iam_role_policy_attachment" "admin" {
  role       = local.admin_role
  policy_arn = data.aws_iam_policy.admin.arn
  depends_on = [module.gh_oidc_roles]
}
