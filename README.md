# Creating Incidents in Sentinel

## Overview  
This repository outlines the steps to configure an alert in Microsoft Sentinel that detects multiple failed logon attempts and automatically creates an incident. Specifically, the alert triggers when more than five failed logon attempts occur within a five-minute window. This setup helps enhance security monitoring by promptly identifying potential brute-force attacks or unauthorized access attempts.

Windows Security Events installed and configured
![image](https://github.com/user-attachments/assets/5d052ca0-70a3-461c-afdc-ba53e563b5a2)
![image](https://github.com/user-attachments/assets/3589bc17-8347-41d2-a62b-bd988edd6b60)
![image](https://github.com/user-attachments/assets/f1556a5c-258a-4a68-8284-7f8962ed1617)

## 1. Analytics - Schedule rule

![image](https://github.com/user-attachments/assets/50e9b703-cca7-4cc4-967d-7f8b3cc7ee15)


**Analytics Rules Wizard**:

  **General**
  - Name = Multiple failed logon attempts
  - Description = Create alert if multiple failed logon attempts detected
  - Severity - Medium
  - Status = Enabled


**Set rule logic**
- Rule query = "SecurityEvent
| where EventID == 4625  // Failed logon attempt
| where AccountType == "User"  // Filter to user accounts (not system accounts)
| summarize FailedAttempts = count() by Account, bin(TimeGenerated, 5m)  // Count failed logins per account every 5 minutes
| where FailedAttempts > 5  // Adjust the threshold as needed, 5 failed attempts within 5 minutes
| project TimeGenerated, Account, FailedAttempts  // Display the relevant fields
| order by TimeGenerated desc  // Sort by time
| take 10  // Limit the results to the latest 10 events"

**Query Scheduling**
- Run query every 30 Minutes
- Lookup data from the last 5 hours

  **Alert threshold**
  - Is greater than 0
 
    Grouped all events into a single Incident

    **Incident Settings**
    - Create Inidents from alerts triggered by this analytics rule = Enabled
   
    - ![image](https://github.com/user-attachments/assets/bcfe4679-5bd4-4a0c-9900-4c05978dc68b)
