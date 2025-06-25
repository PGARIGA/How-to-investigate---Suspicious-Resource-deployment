# How-to-investigate---Suspicious-Resource-deployment

Security Investigation and Response Document
Incident: Unauthorized Deployment / Suspicious Operation in Azure
1. Initial Investigation
Steps:
- Collect Basic Information:
   • User involved
   • IP Address
   • Resource affected
   • Operation Type (e.g., deployment, modification)
   • Start Time & End Time
- Perform IP Investigation:
   • Check IP reputation via security tools (e.g., VirusTotal, Threat Intelligence).
   • Check geolocation and historical usage.
- Check Operation Context:
   • What operation was performed?
   • Validate whether the user holds roles necessary for this operation.
   • Check if these roles are still required.

KQL for Operation Investigation:
AuditLogs
| where TimeGenerated between (datetime(starttime) .. datetime(endtime))
| where Identity contains "<UserEmail>"
| project TimeGenerated, OperationName, Identity, IPAddress, ResultDescription, TargetResources
 
AzureActivity
| where Caller contains "<UserEmail>"
| where ActivityStatusValue == "Success"
| where OperationName contains "Write role assignment"
| project TimeGenerated, Caller, Role, ResourceGroup, SubscriptionId
2. Mid Investigation
Steps:
- Check IP Address History:
   • If IP is new for the user, initiate session revocation.
   • If familiar, proceed to further investigation.
- Check MFA Status:
   • Confirm if the user completed MFA during this session.
- Determine UserAgent:
   • Check if the operation is from:
     ◦ Azure Portal (verify MFA)
     ◦ Powershell / CLI (Check if machine is domain joined)

KQL to Check Sign-in Logs:
SigninLogs
| where UserPrincipalName == "<UserEmail>"
| project TimeGenerated, IPAddress, AppDisplayName, AuthenticationRequirement, Status, DeviceDetail
KQL to Check IP Address History:
SigninLogs
| where UserPrincipalName == "<UserEmail>"
| summarize CountIP = count() by IPAddress
| order by CountIP desc
KQL for UserAgent Check:
SigninLogs
| where UserPrincipalName == "<UserEmail>"
| project TimeGenerated, IPAddress, AppDisplayName, ClientAppUsed, DeviceDetail
3. Final Investigation Checklist
Check	Status
Verify if the IP is part of the user's typical geo-location	Pending
Confirm if the deployment was planned/approved	Pending
Review audit logs for other operations by this user/IP	Pending
Check if any sensitive resources were impacted	Pending
Confirm MFA/Conditional Access was enforced	Pending
Check for any subsequent anomalies from this account/IP	Pending
KQL to Check Sensitive Resources Impact:
AzureActivity
| where Caller contains "<UserEmail>"
| where ActivityStatusValue == "Success"
| project TimeGenerated, OperationName, ResourceGroup, ResourceProviderName, Resource
KQL to Check Anomalies Post-Event:
AuditLogs
| where Identity contains "<UserEmail>" or IPAddress == "<SuspiciousIP>"
| where TimeGenerated > datetime(2025-06-24T00:00:00Z)
| project TimeGenerated, OperationName, Identity, IPAddress, ResultDescription
4. Remediation / Next Steps
If Unauthorized Deployment:
1. Revoke Sessions: From Entra ID → Sign-in Logs → Revoke Session.
2. Reset Password: For User.
3. Review and Restrict Roles: Validate necessity of permissions like Contributor.
4. Lock Resources: Apply resource locks where needed.
5. Enable Defender for Cloud Alerts: For change detection.

If Legitimate Deployment:
- Document the activity.
- Apply Least Privilege Principle moving forward.
- Implement stricter role review and conditional access policies.
![image](https://github.com/user-attachments/assets/5aad5f7d-3f95-4f67-9692-489bda7bfcc2)

