# Infrastructure Fix for Password Reset Environment Variables

**Date**: August 17, 2025  
**Issue**: Password reset failing due to missing environment variables in Auth Lambda function  
**Solution**: Add missing environment variables to CDK infrastructure code  

## 🎯 PROBLEM IDENTIFIED

The Auth Lambda function is missing the `PASSWORD_RESET_TOKENS_TABLE_NAME` environment variable, causing password reset functionality to fail.

### Current Auth Lambda Environment Variables:
```python
environment={
    "PEOPLE_TABLE_NAME": people_table.table_name,
    "AUDIT_LOGS_TABLE_NAME": audit_logs_table.table_name,
    "JWT_SECRET": "your-jwt-secret-change-in-production-please",
    "JWT_EXPIRATION_HOURS": "24",
}
```

### Required Fix:
```python
environment={
    "PEOPLE_TABLE_NAME": people_table.table_name,
    "AUDIT_LOGS_TABLE_NAME": audit_logs_table.table_name,
    "PASSWORD_RESET_TOKENS_TABLE_NAME": password_reset_tokens_table.table_name,  # ← ADD THIS
    "JWT_SECRET": "your-jwt-secret-change-in-production-please",
    "JWT_EXPIRATION_HOURS": "24",
}
```

## 🔧 IMPLEMENTATION

### File to Modify:
`registry-infrastructure/people_register_infrastructure/people_register_infrastructure_stack.py`

### Line Numbers: ~395-400
Update the Auth Lambda environment variables section.

### Additional Required Change:
Grant Auth Lambda access to password reset tokens table:
```python
password_reset_tokens_table.grant_read_write_data(auth_lambda)
```

## 🚀 DEPLOYMENT PROCESS

1. Update CDK infrastructure code
2. Deploy via infrastructure pipeline: `npx cdk deploy --hotswap-fallback`
3. Test password reset functionality
4. Verify environment variables are set correctly

## ✅ VALIDATION

After deployment, verify:
- Auth Lambda has `PASSWORD_RESET_TOKENS_TABLE_NAME` environment variable
- Auth Lambda has permissions to access password reset tokens table
- Password reset functionality works end-to-end
