# DynamoDB Deprecation Fix

## Issue
CDK synthesis was failing due to deprecated `point_in_time_recovery` parameter in DynamoDB table definitions.

## Error Message
```
[WARNING] aws-cdk-lib.aws_dynamodb.TableOptions#pointInTimeRecovery is deprecated.
use `pointInTimeRecoverySpecification` instead
This API will be removed in the next major release.
```

## Solution
Replaced all instances of the deprecated `point_in_time_recovery=True` parameter with the new `point_in_time_recovery_specification` parameter structure.

### Before (Deprecated)
```python
point_in_time_recovery=True,
```

### After (Fixed)
```python
point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
    point_in_time_recovery_enabled=True
),
```

## Tables Updated
The following DynamoDB tables were updated to use the new parameter:

1. **ProjectsTable** - Project data storage
2. **SubscriptionsTable** - Many-to-many relationships
3. **PasswordResetTokensTable** - Password reset tokens with TTL
4. **EmailTrackingTable** - Email delivery tracking with TTL
5. **PasswordHistoryTable** - Password history with TTL
6. **SessionTrackingTable** - Session tracking with TTL
7. **RateLimitTable** - Rate limiting with TTL
8. **CSRFTokenTable** - CSRF token storage with TTL
9. **AuditLogsTable** - Audit logging
10. **AccountLockoutTable** - Account lockout tracking with TTL

## Impact
- ✅ **No Functional Changes**: Point-in-time recovery functionality remains identical
- ✅ **CDK Synthesis Fixed**: Eliminates deprecation warnings and build failures
- ✅ **Future Compatibility**: Uses current CDK API that won't be removed
- ✅ **Backward Compatible**: No changes to existing deployed resources

## Verification
The fix has been committed to the `feature/xray-tracing-infrastructure` branch and should resolve the CDK synthesis errors in the CI/CD pipeline.

## Related Changes
This fix was applied alongside the X-Ray tracing implementation to ensure the infrastructure deployment succeeds.
