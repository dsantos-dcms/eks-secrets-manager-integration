## Pre Requisites

## Create an OIDC Identity Provider - Allow Kubernetes (EKS) service accounts to assume IAM roles, This is a common use case
## where an OIDC provider for EKS is used to grant specific permissions to pods within the cluster.

## 1 - Create or associate OIDC Identity Provider to the cluster
eksctl utils associate-iam-oidc-provider --region="$REGION" --cluster="$CLUSTERNAME" --approve

## 2 -  Create a policy to allow READ SECRETS as per Below
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
            "Resource": "*"
        }
    ]
}
# or Granular (Specify Secret ARN)
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
            "Resource": ["arn:aws:secretsmanager:ca-central-1:292384479065:secret:customer-a-mR9HPa"]
        }
    ]
}

## 3 - Create the CLUSTER IAM EKS ServiceAccount and associate the policy with it

eksctl create iamserviceaccount --name secret-manager-service-account --region "ca-central-1" --cluster "eks-dsantos" --attach-policy-arn "arn:aws:iam::292384479065:policy/EKSSecretsManagerPolicy" --approve --override-existing-serviceaccounts

# Alternatively you can also create a role manually via AWS console or terraform and add the service account via YAML referecing the role ARN.
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: secret-manager-service-account
  namespace: app
  annotations:
    # Replace with the updated arn role
    eks.amazonaws.com/role-arn: arn:aws:iam::292384479065:role/eks-secret-manager-role

## 4 - Confirm the iamserviceaccount creation | If created by EKSCTL
eksctl get iamserviceaccount --region ca-central-1 --cluster eks-dsantos --name aws-sm-customera

## 5 - Install the Secrets Store CSI Driver and Provider by following the steps on Secrets Store CSI Driver.MD and Secrets Store CSI Provider.MD

## 6 - Deploy the resources on the manifest folder

## 7 - You can test if the password has been sucesfully pulled from AWS by looking at the logs from the pods or decoding the K8Ssecret Object
- kubectl get secret rds-password -n app -o=jsonpath='{.data.rds_pwd}' | base64 --decode 
- k logs pod -n namespace

