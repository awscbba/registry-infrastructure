# GitHub Actions Workflows

This directory contains GitHub Actions workflows for automated CI/CD of the infrastructure.

## Workflows

### 1. Infrastructure Deployment (`infrastructure-deployment.yml`)

**Triggers:**
- Push to `main` branch (automatic deployment)
- Pull requests to `main` (validation only)
- Manual trigger via GitHub UI

**Jobs:**
- **Validate:** Runs CDK synthesis to validate infrastructure code
- **Deploy:** Deploys infrastructure to AWS (only on main branch pushes)

**Requirements:**
- AWS credentials configured via OIDC
- `AWS_ROLE_ARN` secret configured in repository settings

### 2. PR Validation (`pr-validation.yml`)

**Triggers:**
- Pull requests to `main` branch

**Jobs:**
- **Validate:** Runs CDK synthesis and diff
- Posts validation results as PR comment
- Uploads synthesis artifacts

## Setup Instructions

### 1. Configure AWS OIDC Provider

First, create an OIDC provider in AWS IAM:

```bash
# This is typically done once per AWS account
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1
```

### 2. Create IAM Role for GitHub Actions

Create an IAM role with the following trust policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::YOUR_ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:awscbba/registry-infrastructure:*"
        }
      }
    }
  ]
}
```

Attach the following managed policies to the role:
- `AdministratorAccess` (or create a custom policy with CDK deployment permissions)

### 3. Configure GitHub Repository Secrets

Add the following secret to your GitHub repository:

1. Go to: `Settings` → `Secrets and variables` → `Actions`
2. Click `New repository secret`
3. Add:
   - **Name:** `AWS_ROLE_ARN`
   - **Value:** `arn:aws:iam::YOUR_ACCOUNT_ID:role/GitHubActionsRole`

### 4. Enable GitHub Actions

1. Go to: `Settings` → `Actions` → `General`
2. Under "Actions permissions", select "Allow all actions and reusable workflows"
3. Under "Workflow permissions", select "Read and write permissions"

## Monitoring Workflows

### View Workflow Runs

1. Go to the `Actions` tab in the GitHub repository
2. Select a workflow from the left sidebar
3. Click on a specific run to see details

### View Logs

1. Click on a workflow run
2. Click on a job name to see its logs
3. Expand steps to see detailed output

### Manual Deployment

To manually trigger a deployment:

1. Go to `Actions` tab
2. Select "Infrastructure Deployment" workflow
3. Click "Run workflow"
4. Select the branch and click "Run workflow"

## Workflow Status Badges

Add these badges to your README:

```markdown
[![Infrastructure Deployment](https://github.com/awscbba/registry-infrastructure/actions/workflows/infrastructure-deployment.yml/badge.svg)](https://github.com/awscbba/registry-infrastructure/actions/workflows/infrastructure-deployment.yml)

[![PR Validation](https://github.com/awscbba/registry-infrastructure/actions/workflows/pr-validation.yml/badge.svg)](https://github.com/awscbba/registry-infrastructure/actions/workflows/pr-validation.yml)
```

## Troubleshooting

### Authentication Errors

If you see authentication errors:
1. Verify the OIDC provider is configured correctly
2. Check the IAM role trust policy
3. Ensure the `AWS_ROLE_ARN` secret is set correctly

### CDK Synthesis Failures

If CDK synthesis fails:
1. Check the Python dependencies in `requirements.txt`
2. Verify Node.js version compatibility
3. Review the workflow logs for specific errors

### Deployment Failures

If deployment fails:
1. Check AWS CloudFormation console for stack errors
2. Review IAM permissions for the GitHub Actions role
3. Check for resource conflicts or limits

## Migration from CodeCatalyst

These workflows replace the CodeCatalyst workflows in `.codecatalyst/workflows/`. 

**Key Differences:**
- Uses GitHub Actions instead of CodeCatalyst
- Uses OIDC for AWS authentication (no long-lived credentials)
- Provides PR comments with infrastructure changes
- Integrated with GitHub's native CI/CD features

**To complete migration:**
1. Set up AWS OIDC and IAM role (see above)
2. Configure repository secrets
3. Test workflows with a PR
4. Once validated, you can remove `.codecatalyst/` directory
