# Justfile Usage Guide

This project uses [just](https://github.com/casey/just) as a command runner to automate common tasks. The justfile replaces the previous `scripts/deploy-frontend.sh` and `deploy-all.sh` scripts with a more structured and feature-rich approach.

## Installation

First, install `just`:

### macOS
```bash
brew install just
```

### Linux
```bash
# Using cargo
cargo install just

# Or download binary from GitHub releases
curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh | bash -s -- --to ~/bin
```

### Windows
```bash
# Using scoop
scoop install just

# Using cargo
cargo install just
```

## Quick Start

```bash
# Show all available commands
just

# Show detailed help
just help

# Complete deployment (replaces deploy-all.sh)
just deploy-all-comprehensive

# Deploy everything (infrastructure + frontend)
just deploy-all

# Deploy only frontend
just deploy-frontend

# Quick frontend deployment (skip dependency installation)
just quick-deploy-frontend

# Start frontend development server
just dev-frontend

# Show current deployment information
just show-info
```

## Key Features

### 🚀 **Complete Deployment Pipelines**
- **`just deploy-all-comprehensive`** - Complete deployment with testing (replaces `deploy-all.sh`)
- **`just deploy-all-from-repos`** - Multi-repository deployment (clones repos first)
- **`just deploy-all`** - Deploy infrastructure and frontend (local repos)

### 🏗️ **Infrastructure Management**
- **`just deploy-infrastructure-full`** - Deploy infrastructure with comprehensive output handling
- **`just cdk-deploy`** - Deploy AWS infrastructure
- **`just cdk-destroy`** - Destroy AWS infrastructure
- **`just cdk-diff`** - Show infrastructure changes
- **`just cdk-bootstrap`** - Bootstrap CDK

### 🎨 **Frontend Management**
- **`just deploy-frontend-full`** - Deploy frontend with environment configuration
- **`just deploy-frontend`** - Deploy frontend only (standard pipeline)
- **`just quick-deploy-frontend`** - Fast frontend deployment (skips npm install)
- **`just build-frontend`** - Build frontend application
- **`just install-frontend-deps`** - Install frontend dependencies

### 🧪 **Testing & Validation**
- **`just test-api`** - Test API endpoints
- **`just test-frontend`** - Test frontend deployment
- **`just create-test-data`** - Create sample data in the application
- **`just validate-deployment`** - Validate deployment status

### 🔧 **Development Workflow**
- **`just dev-frontend`** - Start development server with API URL configured
- **`just check-prerequisites`** - Verify required tools are installed
- **`just extract-outputs`** - Extract and display deployment outputs

### 🗂️ **Repository Management**
- **`just setup-workspace`** - Setup workspace for multi-repo deployment
- **`just clone-repos`** - Clone all repositories
- **`just cleanup-workspace`** - Clean up temporary workspace
- **`just cleanup-interactive`** - Interactive cleanup prompt

### 🧹 **Cleanup Operations**
- **`just clean-frontend`** - Remove build artifacts
- **`just clean-frontend-deps`** - Remove node_modules
- **`just clean-all`** - Complete cleanup

### ℹ️ **Information & Debugging**
- **`just show-info`** - Display stack outputs and URLs
- **`just print-deployment-summary`** - Print comprehensive deployment summary
- **`just show-logs`** - Show recent CloudFormation events

## Migration from Shell Scripts

The justfile provides all the functionality of the previous scripts plus additional features:

| Shell Script | Justfile Equivalent | Notes |
|-------------|-------------------|-------|
| `./deploy-all.sh` | `just deploy-all-comprehensive` | Complete pipeline with testing |
| `./scripts/deploy-frontend.sh` | `just deploy-frontend` | Full frontend pipeline |
| N/A | `just quick-deploy-frontend` | New: Skip deps |
| N/A | `just dev-frontend` | New: Dev server |
| N/A | `just show-info` | New: Stack info |
| N/A | `just validate-deployment` | New: Health checks |
| N/A | `just deploy-all-from-repos` | New: Multi-repo deployment |

## CodeCatalyst Integration

The justfile is fully integrated with CodeCatalyst workflows located in `.codecatalyst/workflows/`:

### Available Workflows:
- **`deploy-infrastructure.yml`** - Infrastructure deployment with environment-specific deployments
- **`complete-deployment.yml`** - Complete application deployment using justfile
- **`development.yml`** - Development workflow for feature branches and testing

### Workflow Commands:
The CodeCatalyst workflows use these justfile commands:
- `just check-prerequisites` - Environment validation
- `just deploy-all-comprehensive` - Complete deployment pipeline
- `just deploy-infrastructure-full` - Infrastructure deployment
- `just deploy-frontend-full` - Frontend deployment with environment configuration
- `just test-api` and `just test-frontend` - Testing
- `just validate-deployment` - Post-deployment validation

## Advantages over Shell Scripts

### ✅ **Better Organization**
- Clear task separation and dependencies
- Built-in help system
- Consistent command interface

### ✅ **Enhanced Functionality**
- Individual task execution
- Dependency management between tasks
- Better error handling and colored output
- Multi-repository support

### ✅ **Developer Experience**
- Tab completion support
- Self-documenting commands
- Cross-platform compatibility
- IDE integration

### ✅ **CI/CD Integration**
- Native CodeCatalyst workflow integration
- Artifact management
- Environment-specific deployments
- Comprehensive reporting

### ✅ **Flexibility**
- Easy to extend with new tasks
- Conditional execution
- Environment variable handling
- Workspace management

## Common Workflows

### Initial Setup
```bash
# Bootstrap and deploy everything
just check-prerequisites
just cdk-bootstrap
just deploy-all-comprehensive
```

### Development Cycle
```bash
# Start development
just dev-frontend

# After making changes, quick deploy
just quick-deploy-frontend
```

### Production Deployment
```bash
# Complete deployment with all checks
just deploy-all-comprehensive

# Validate everything is working
just validate-deployment
```

### Multi-Repository Deployment
```bash
# Deploy from CodeCatalyst repositories
just deploy-all-from-repos

# Clean up afterward
just cleanup-interactive
```

### Troubleshooting
```bash
# Check current status
just show-info

# View recent events
just show-logs

# Validate deployment
just validate-deployment

# Print comprehensive summary
just print-deployment-summary
```

## Environment Variables

The justfile automatically handles environment variables:
- `PUBLIC_API_URL` - Set from CloudFormation outputs
- Stack outputs are retrieved dynamically
- No manual configuration required
- Environment files are generated automatically

## Error Handling

The justfile includes comprehensive error handling:
- Requirement checks (AWS CLI, npm, Python, Git, jq)
- Stack output validation
- Build failure detection
- API endpoint testing
- Colored output for better visibility
- Detailed error messages

## Customization

You can easily customize the justfile by:
- Modifying the `STACK_NAME` variable
- Adjusting the `FRONTEND_DIR` and `API_DIR` paths
- Updating CodeCatalyst repository URLs
- Adding new tasks for your specific needs
- Extending the help documentation

## CodeCatalyst Workflow Triggers

### Automatic Triggers:
- **Push to main:** Triggers production deployment
- **Push to develop:** Triggers development deployment
- **Pull Requests:** Triggers validation and testing
- **Feature branches:** Triggers development testing

### Manual Triggers:
- Complete deployment workflow can be triggered manually
- Individual justfile commands can be run locally

## Best Practices

### Local Development:
```bash
# Always check prerequisites first
just check-prerequisites

# Use development workflow
just dev-frontend

# Test changes locally before pushing
just build-frontend
```

### Production Deployment:
```bash
# Use comprehensive deployment
just deploy-all-comprehensive

# Always validate after deployment
just validate-deployment

# Check deployment summary
just print-deployment-summary
```

### Troubleshooting:
```bash
# Check current state
just show-info

# View logs for issues
just show-logs

# Clean up if needed
just clean-all
```

For more information about just syntax and features, visit: https://just.systems/man/en/

For CodeCatalyst workflow documentation, see: `.codecatalyst/README.md`
