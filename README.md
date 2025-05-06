# Suspicious Sign-In Detection with Azure AD SigninLogs

This project uses KQL to detect suspicious sign-in attempts in Azure AD SigninLogs, identifying anomalies like impossible travel or excessive failed logins.

## Usage
Run in Azure Sentinel to flag users with >5 failed logins or logins from >2 locations in 7 days. Ideal for detecting compromised accounts or brute-force attempts.

## Compliance Alignment
This project supports compliance with standards like NIST 800-53 (SI-4: Information System Monitoring) by detecting unauthorized access attempts (e.g., 200 failed logins). Queries can be adapted for audit logging or HIPAA security rule requirements—ensuring traceability and risk management.

## Query
```kql
SigninLogs
| where TimeGenerated > ago(7d)
| summarize LoginAttempts = count(), FailedAttempts = countif(ResultType != "0"), Locations = make_set(Location), IPs = make_set(IPAddress) by UserPrincipalName
| where FailedAttempts > 5 or array_length(Locations) > 2
| extend SuspiciousTravel = iif(array_length(Locations) > 2, "Yes", "No")
| project UserPrincipalName, LoginAttempts, FailedAttempts, Locations, IPs, SuspiciousTravel
| order by FailedAttempts desc, LoginAttempts desc
