# CodeCatalyst Workflows for People Register Infrastructure

This directory contains CodeCatalyst workflow definitions that implement a **merge-approval-based deployment strategy**. Production deployments only occur after pull requests are approved and merged into the main branch.

## Cross-Repository Coordination

### **Multi-Repository Deployment Strategy**
The infrastructure repository now serves as the central coordination point for deployments triggered by changes in any of the three repositories:

1. **🏗️ people-register-infrastructure**: Direct infrastructure changes
2. **🔧 people-register-api**: API changes that trigger full deployment
3. **🎨 people-register-frontend**: Frontend changes that trigger full deployment

### **Cross-Repository Workflow Triggers**
- API and Frontend repositories can trigger infrastructure deployment
- Uses AWS CLI to start workflows across repositories
- Provides deployment context and coordination
- Maintains audit trail across all repositories

### **New Workflow: `cross-repo-deployment.yml`**
**Purpose:** Handle deployments triggered by other repositories

**Triggers:**
- ✅ Manual execution (for cross-repository triggers)
- ✅ Push to `main` branch (for direct infrastructure changes)

**Features:**
- Deployment source identification
- Comprehensive deployment using justfile
- Cross-repository coordination and reporting
- Detailed deployment tracking and notifications

## Workflow Files

### 1. `deploy-infrastructure.yml` ⭐ **PRIMARY DEPLOYMENT WORKFLOW**
**Purpose:** Main production deployment workflow triggered by approved merges

**Triggers:**
- ✅ Push to `main` branch (after approved merge)
- ✅ Pull requests to `main` branch (validation only)

**Deployment Behavior:**
- **Pull Requests**: Validation and testing only (NO deployment)
- **Main Branch Push**: Full production deployment pipeline

**Actions:**
- Install just command runner
- Validate infrastructure code (always)
- **Deploy to production** (ONLY on main branch push)
- Deploy frontend after infrastructure
- Run integration tests
- Send deployment success notification

### 2. `merge-to-production.yml` 🎯 **MERGE-SPECIFIC WORKFLOW**
**Purpose:** Dedicated workflow for tracking and managing production deployments

**Triggers:**
- ✅ Push to `main` branch ONLY (after approved merge)

**Features:**
- Pre-deployment validation and logging
- Comprehensive deployment tracking
- Post-deployment validation
- Detailed deployment reporting
- Success notifications with full context

### 3. `complete-deployment.yml` 🚀 **COMPREHENSIVE DEPLOYMENT**
**Purpose:** Alternative complete deployment pipeline

**Triggers:**
- ✅ Push to `main` branch (after approved merge)
- ✅ Manual execution (for emergency deployments)

**Features:**
- Uses `just deploy-all-comprehensive` command
- Includes performance testing
- Generates comprehensive reports

### 4. `development.yml` 🔧 **DEVELOPMENT VALIDATION**
**Purpose:** Feature branch and pull request validation (NO DEPLOYMENT)

**Triggers:**
- ✅ Push to `develop` or `feature/*` branches
- ✅ Pull requests to `main` or `develop` branches

**Actions:**
- Code validation and testing
- Security scanning
- Pull request approval guidance
- Feature branch development feedback

**Important:** This workflow does NOT deploy infrastructure

## 🔐 Security and Approval Process

### **Required Workflow:**
1. **Feature Development** → Push to `feature/branch-name`
   - Triggers: `development.yml` (validation only)
   - Result: Code validation and security scanning

2. **Pull Request Creation** → Create PR to `main`
   - Triggers: `development.yml` and `deploy-infrastructure.yml` (validation only)
   - Result: Comprehensive validation, no deployment

3. **Code Review and Approval** → Team reviews and approves PR
   - Manual process: Code review, approval, merge

4. **Production Deployment** → Merge approved PR to `main`
   - Triggers: `deploy-infrastructure.yml`, `merge-to-production.yml`, `complete-deployment.yml`
   - Result: **AUTOMATIC PRODUCTION DEPLOYMENT**

### **Key Security Features:**
- 🔒 **No Direct Deployment**: Feature branches cannot deploy to production
- 🔍 **Mandatory Review**: All production changes require PR approval
- 🧪 **Pre-Deployment Validation**: Comprehensive testing before deployment
- 📊 **Deployment Tracking**: Full audit trail of all deployments
- 🚨 **Rollback Ready**: Clear deployment history for rollback procedures

## Environment Setup

### Required Environments

1. **production** (ONLY environment needed)
   - Connection: `aws-connection`
   - Role: `CodeCatalystWorkflowProductionRole-us-west-2`

### **Removed Development Environment**
- No separate development environment deployments
- All validation happens without deployment
- Reduces complexity and costs
- Focuses on production-ready code

## Workflow Execution Flow

### **Feature Development Flow**
```
Feature Branch Push → Code Validation → Security Scanning → 
Ready for PR Creation
```

### **Pull Request Flow**
```
Create PR → Validation (No Deployment) → Code Review → 
Approval → Merge to Main
```

### **Production Deployment Flow (After Merge)**
```
Merge to Main → Pre-Deployment Check → Infrastructure Deployment → 
API Testing → Frontend Deployment → Integration Tests → 
Success Notification → Deployment Report
```

## 🎯 Key Benefits

### **1. Controlled Deployments**
- Production deployments only after explicit approval
- No accidental deployments from feature branches
- Clear audit trail of all changes

### **2. Improved Code Quality**
- Mandatory code review process
- Comprehensive validation before deployment
- Security scanning on all changes

### **3. Reduced Risk**
- No direct production access from development
- Validated code paths only
- Automated rollback capabilities

### **4. Better Collaboration**
- Clear review and approval process
- Team visibility into all changes
- Documented deployment history

## Usage Examples

### **Feature Development**
```bash
# Create and work on feature branch
git checkout -b feature/new-functionality
git push origin feature/new-functionality

# Workflow automatically runs validation (no deployment)
# Continue development based on validation results
```

### **Production Deployment**
```bash
# Create pull request to main
# Request code review from team members
# Address review feedback
# Obtain approval from required reviewers

# Merge to main (triggers automatic production deployment)
git checkout main
git merge feature/new-functionality
git push origin main

# Production deployment automatically starts
```

### **Emergency Manual Deployment**
```bash
# Use manual trigger in CodeCatalyst console
# Go to complete-deployment.yml workflow
# Click "Run workflow" button
# Confirm manual execution
```

## Monitoring and Notifications

### **Deployment Notifications**
- 📧 Success notifications with deployment details
- 🚨 Failure alerts with error information
- 📊 Deployment reports with comprehensive details

### **Audit Trail**
- Complete deployment history
- Commit tracking and author information
- Deployment timing and duration
- Validation results and test outcomes

## Migration Benefits

### **From Previous Setup:**
- ❌ **Before**: Manual deployments and multiple environments
- ✅ **After**: Automated merge-based deployments

### **Improved Security:**
- ❌ **Before**: Direct deployment access from any branch
- ✅ **After**: Deployment only after approval and merge

### **Better Process:**
- ❌ **Before**: Ad-hoc deployment decisions
- ✅ **After**: Structured review and approval process

## Best Practices

### **1. Branch Protection**
- Enable branch protection rules on `main` branch
- Require pull request reviews before merging
- Require status checks to pass before merging
- Restrict push access to `main` branch

### **2. Code Review Process**
- Require at least one approval before merge
- Use meaningful commit messages
- Test changes locally before creating PR
- Address all review feedback before merge

### **3. Deployment Monitoring**
- Monitor workflow execution in CodeCatalyst console
- Check deployment reports for any issues
- Verify application functionality after deployment
- Set up CloudWatch alarms for application monitoring

### **4. Emergency Procedures**
- Use manual deployment workflow for emergencies
- Document rollback procedures
- Maintain deployment history for reference
- Have team contact information readily available

## Troubleshooting

### **Common Scenarios**

1. **PR Validation Fails**
   - Check validation logs in CodeCatalyst
   - Fix code issues in feature branch
   - Push updates to trigger re-validation

2. **Deployment Fails After Merge**
   - Check deployment logs in production environment
   - Use manual rollback if necessary
   - Create hotfix branch for urgent fixes

3. **Approval Process Issues**
   - Ensure required reviewers are available
   - Check branch protection settings
   - Verify team permissions and access

### **Emergency Contacts**
- DevOps Team: [Contact Information]
- AWS Support: [Support Plan Details]
- Team Lead: [Contact Information]

This merge-approval-based deployment strategy ensures that all production deployments are controlled, validated, and properly approved while maintaining development velocity and code quality.
