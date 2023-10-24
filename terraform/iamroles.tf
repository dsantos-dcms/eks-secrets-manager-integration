resource "aws_iam_policy" "secret_manager_policy" {
  name        = "EKSSecretsManagerPolicy"
  description = "Policy that allows KMS and SecretsManager actions"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect    = "Allow"
        Action    = [
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService"    = ["secretsmanager.*.amazonaws.com"]
          }
        }
      },
      {
        Effect    = "Allow"
        Action    = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = "*"
      }
    ]
  })
}

# Create a role that can be assumed by our service account
module "iam-assumable-role-with-oidc-just-like-iam-role-attachment-to-ec2" {
    source  = "terraform-aws-modules/iam/aws//modules/iam-assumable-role-with-oidc"
    version = "5.10.0"

    create_role      = true
    role_name        = "eks-secret-manager-role"
    provider_url     = "https://oidc.eks.ca-central-1.amazonaws.com/id/8DCBCA5AFA935AC66F13AA68D6963784" # GET OIDC 
    role_policy_arns = [
      aws_iam_policy.secret_manager_policy.arn
    ]
}