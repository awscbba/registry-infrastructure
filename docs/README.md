# Registry Infrastructure Documentation

This directory contains comprehensive documentation for the registry-infrastructure repository deployment workflows and coordination system.

## 📁 Documentation Structure

```
docs/
├── README.md                           # This file - Documentation overview
├── workflows/
│   ├── README.md                      # CodeCatalyst workflows documentation
│   ├── infrastructure-deployment.md   # Infrastructure deployment pipeline
│   ├── deployment-coordination.md     # Cross-repository coordination
│   ├── pr-validation-workflow.md      # Pull request validation workflow
│   └── pr-validation-troubleshooting.md # PR validation troubleshooting guide
├── team-processes/
│   └── pr-validation-process.md        # Team PR validation guidelines
├── deployment/
│   ├── coordination-guide.md          # Deployment coordination guide
│   ├── rollback-procedures.md         # Emergency rollback procedures
│   └── monitoring.md                  # Monitoring and observability
├── security/
│   ├── handler-security.md            # Handler security considerations
│   └── cross-repo-security.md         # Cross-repository security
└── templates/
    └── pr-template.md                  # Pull request template
```

## 🎯 Quick Start

1. **New to the project?** Start with [workflows/README.md](workflows/README.md)
2. **Creating a PR?** See [workflows/pr-validation-workflow.md](workflows/pr-validation-workflow.md) and [team-processes/pr-validation-process.md](team-processes/pr-validation-process.md)
3. **PR validation issues?** Check [workflows/pr-validation-troubleshooting.md](workflows/pr-validation-troubleshooting.md)
4. **Deploying changes?** See [deployment/coordination-guide.md](deployment/coordination-guide.md)
5. **Using PR template?** Use [templates/pr-template.md](templates/pr-template.md)

## 🔗 Related Documentation

- **Registry-API**: `../registry-api/docs/` - API implementation and workflows
- **Registry-Frontend**: `../registry-frontend/docs/` - Frontend integration
- **Specifications**: `../.kiro/specs/person-crud-completion/` - Feature specifications

## 📊 Documentation Maintenance

This documentation is maintained alongside the codebase. When making changes:

1. Update relevant documentation files
2. Verify all links and references
3. Update the last modified date
4. Test any code examples or procedures

**Last Updated**: July 24, 2025