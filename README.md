# Azure Sentinel Honeypot Lab
![winnie-the-pooh-pooh](https://github.com/user-attachments/assets/64bc52e5-92bc-4800-ac5f-946360d274c8)

## Objective
The aim of this honeypot lab is to create a controlled environment for monitoring and analyzing live cyber-attacks in real time. The focus is on ingesting and analyzing logs in a Security Information and Event Management (SIEM) system to provide insights into global attack patterns followed by a comprehensive analysis and report.

## Skills Learned
- Advanced understanding of SIEM concepts and practical application.
- Proficiency in analyzing and interpreting logs.
- Ability to generate and recognize attack signatures and patterns.
- Enhanced knowledge of network protocols and security vulnerabilities.
- Development of critical thinking and problem-solving skills.

## Steps

### Step 1: Set Up an Azure Free Trial
- Navigate to Azure and set up a free trial.
- Sign up and verify your account—you’ll receive $200 in free credits.
- Provide necessary personal information to complete registration.

![image](https://github.com/user-attachments/assets/78fe0bb2-a2b1-479c-9fde-5e50aafa215e)

### Step 2: Create a Virtual Machine (VM)
- In Azure, create a new Virtual Machine (VM) to serve as your monitored device.
- Set up a new Resource Group (e.g., name it "HoneypotVM").
- Choose VM specifications:
  - Select "Windows 10 Pro" as the operating system.
  - Set a username (e.g., honeypot) and a strong password.
  - Enable RDP (Remote Desktop Protocol) to allow remote connections, exposing port 3389.
- Review and create the VM. Azure will allocate a public IP automatically.

![image](https://github.com/user-attachments/assets/395cd4af-78bc-4577-bbb1-7cf8cb7b9db7)

![image](https://github.com/user-attachments/assets/44943a55-b76a-4130-a87f-0a2716c500a1)

### Step 3: Configure Microsoft Sentinel
- Deploy Microsoft Sentinel to monitor and collect security events.
- Search for "Sentinel" in Azure and click “Create Microsoft Sentinel.”
- Add Sentinel to your Resource Group (the same one you created in Step 2).
- Select the same region as your VM to ensure performance.
- Review and create the log analytics workspace for Sentinel.
- Monitor deployment progress in the Notifications tab.

![image](https://github.com/user-attachments/assets/af093365-a5b2-4d5e-a967-0ad712b05339)

![image](https://github.com/user-attachments/assets/f61f0824-e21c-4a00-8fc3-08f02bc346ab)

![image](https://github.com/user-attachments/assets/25bcc4dc-8ee6-4270-aa32-242ef166dd4a)

![image](https://github.com/user-attachments/assets/c398f0fb-71ac-4424-905e-479cfa6ebc2a)

### Step 4: Connect VM Logs to Sentinel
- Wait for VM and Sentinel workspace to deploy.
- Go to the Sentinel overview and select “Log Analytics Workspace.”
- Add VM logs to the Sentinel log workspace:
  - Navigate to “Agents” in the log workspace.
  - Ensure the VM is set up to log security events.
- Set up a Data Connector:
  - Use the "Azure Monitor Agent (AMA)" connector for your VM logs.
  - Install the AMA connector through the Content Hub and refresh your data connectors list.
- Create a Data Collection Rule:
  - Name it (e.g., "Windows Events to Sentinel").
  - Select "Honeypot VM" as the resource and choose "All Security Events."

![image](https://github.com/user-attachments/assets/94b46108-0649-4029-822b-93673965ce81)

![image](https://github.com/user-attachments/assets/29f4e6da-9efb-44a8-a75c-f2666e6fc65f)

![image](https://github.com/user-attachments/assets/6661597a-3551-4af4-bc7e-3bee1a791086)

![image](https://github.com/user-attachments/assets/7580a2e1-1871-4a52-b026-a9d9e9c91ef7)

![image](https://github.com/user-attachments/assets/72707aed-07fc-4ffc-a555-6458ca6dea81)

![image](https://github.com/user-attachments/assets/4353cb86-9e6c-43aa-a417-52c379b35ce9)


### Step 5: Configure Sentinel Rules for Alerts
- Create a Sentinel rule to generate alerts for specific events (e.g., successful RDP sign-ins):
  - Go to the Analytics tab in Sentinel.
  - Set up a new rule for “Successful Local Sign-Ins” and adjust severity (e.g., "Initial Access").
  - Configure the rule to run every 5 minutes for real-time alerts.
  - Set an alert threshold so that an alert is generated after each successful login attempt.
  - Review and save the rule to activate it.

![388803337-64d84a28-caf1-436a-94c5-81f869c59604](https://github.com/user-attachments/assets/8d749cf5-d13f-40f1-a017-ad73c87bc410)





### Step 6: Test and Verify Sentinel Alerts
- Check the Analytics page for the new rule you created.
- Monitor the Incidents page to see if a new alert appears.
- Confirm that the rule captures successful login events and generates alerts accordingly.





![image](https://github.com/user-attachments/assets/926fe3aa-950b-4e4c-b316-0956b1ed9d7b)

![image](https://github.com/user-attachments/assets/8272dea4-6d48-4ab5-a1e5-582f2e79dba1)

![image](https://github.com/user-attachments/assets/30b1dba8-3394-4dab-b9b3-e02814de7f22)



# The Analysis

## 1. Frequent Security Events
- The dataset predominantly consists of EventID 4625, which corresponds to "An account failed to log on." This indicates repeated failed authentication attempts.
- These events show definite security risks, particularly brute-force attacks & unauthorized access attempts.

## All attacks that were performed on my Honey Pot 

| **Attacks performed**                                 | **Event ID** | **Event Description**                                                                                   |
|-------------------------------------------------------|--------------|---------------------------------------------------------------------------------------------------------|
| **Event Logging Service Shutdown**                   | 1100         | The event logging service has shut down.                                                               |
| **Windows Startup**                                   | 12           | The operating system has started up.                                                                   |
| **System Time Change**                                | 4616         | The system time was changed.                                                                           |
| **Successful Account Logon**                         | 4624         | An account was successfully logged on.                                                                 |
| **Failed Account Logon**                              | 4625         | An account failed to log on.                                                                           |
| **Logon Using Explicit Credentials**                 | 4648         | A logon was attempted using explicit credentials.                                                      |
| **Special Privileges Assigned to Logon**             | 4672         | Special privileges assigned to new logon.                                                              |
| **New Process Creation**                              | 4688         | A new process has been created.                                                                        |
| **Primary Token Assigned to Process**                | 4696         | A primary token was assigned to a process.                                                             |
| **Local Group Membership Enumeration**               | 4798         | A user's local group membership was enumerated.                                                        |
| **Security-Enabled Group Enumeration**               | 4799         | A security-enabled local group membership was enumerated.                                              |
| **Boot Configuration Data Loaded**                   | 100          | Boot Configuration Data loaded.                                                                        |
| **Per-User Audit Policy Created**                    | 4906         | The Per-user audit policy table was created.                                                           |
| **Windows Firewall Service Started**                 | 5032         | Windows Firewall Service has started successfully.                                                     |
| **Windows Firewall Driver Started**                  | 2004         | The Windows Firewall Driver has started successfully.                                                  |
| **Key File Operation**                                | 4662         | An operation was performed on an object.                                                              |
| **Key Migration Operation**                          | 4692         | A key migration operation was performed.                                                               |
| **Cryptographic Operation**                          | 5061         | Cryptographic operation.                                                                               |

---

## 2. Targeted Accounts
- Accounts such as `ADMINISTRATOR`, `DELL`, and `VMADMIN` were repeatedly targeted. These accounts hold elevated privileges, making them attractive to attackers.
- The `TargetAccount` and `TargetUserName` reveal a focus on both specific named accounts and more generic account types, implying varying levels of targeting strategy.

## 3. IP Address Analysis
- The `IpAddress` column revealed numerous sources for failed login attempts. Notable findings include:
  - Diverse IP ranges suggest attempts from different geographic locations, indicating the use of botnets or distributed attack tools.
  - A lack of IP addresses for some entries imply intentional masking by attackers.
    
# Malicious IP Address's I found

| **IP Address**      | **Hostname**                                  | **Country**       | **Region**         | **City**              | **Provider**                                   | **ASN**   |
|---------------------|----------------------------------------------|-------------------|--------------------|-----------------------|-----------------------------------------------|-----------|
| 103.142.87.50       |                                              | Hong Kong         |                    |                       | YISU CLOUD LTD                                | 138152    |
| 103.227.210.199     |                                              | India             | Maharashtra        | Mumbai                | SRMAK TECHNOLOGICAL SYSTEM PRIVATE LIMITED    | 151106    |
| 104.210.220.129     |                                              | United States     | Texas              | San Antonio           | MICROSOFT-CORP-MSN-AS-BLOCK                  | 8075      |
| 116.228.169.194     |                                              | China             | Shanghai           | Shanghai              | China Telecom Group                           | 4812      |
| 120.133.88.0        |                                              | China             |                    |                       | IDC, China Telecommunications Corporation     | 23724     |
| 121.146.41.34       |                                              | South Korea       | Ulsan              | Jung-gu              | Korea Telecom                                 | 4766      |
| 141.95.82.247       | ip247.ip-141-95-82.eu                        | France            |                    |                       | OVH SAS                                       | 16276     |
| 141.95.82.248       | ip248.ip-141-95-82.eu                        | France            |                    |                       | OVH SAS                                       | 16276     |
| 141.98.83.170       |                                              | Panama            |                    |                       | Flyservers S.A.                               | 209588    |
| 144.217.111.52      | ip52.ip-144-217-111.net                      | Canada            | Quebec             | Beauharnois           | OVH SAS                                       | 16276     |
| 157.55.138.57       |                                              | United States     | Illinois           | Chicago               | MICROSOFT-CORP-MSN-AS-BLOCK                  | 8075      |
| 159.242.234.232     |                                              | Germany           | Hesse              | Frankfurt am Main     | AVAST Software s.r.o.                        | 198605    |
| 160.179.55.145      |                                              | Morocco           | Casablanca         | Casablanca            | MT-MPLS                                       | 36903     |
| 162.210.245.77      |                                              | United States     | Virginia           | Ashburn               | SNEAKER-SERVER                                | 397651    |
| 177.34.6.189        | b12206bd.virtua.com.br                       | Brazil            | Mato Grosso do Sul | Campo Grande          | Claro NXT Telecomunicacoes Ltda              | 28573     |
| 177.4.107.235       | 177-4-107-235.user3p.v-tal.net.br            | Brazil            | Paraná             | Pinhais               | V tal                                        | 8167      |
| 179.0.57.108        | 179-0-57-108.zentelecom.com.br               | Brazil            | Santa Catarina     | Florianópolis         | ZEN INTERNET E TELECOMUNICACAO EIRELI        | 271498    |
| 181.177.12.111      | 181-177-12-111.fiberway.com.ar               | Argentina         | Jujuy              | San Salvador de Jujuy | TELESISTEMA S.R.L.                           | 264642    |
| 185.170.144.185     |                                              | Estonia           |                    |                       | Xhost Internet Solutions Lp                  | 197414    |
| 186.75.215.94       |                                              | Panama            | Provincia de Panamá| Panama City           | Cable & Wireless Panama                      | 11556     |
| 189.112.15.18       | 189-112-015-018.static.ctbctelecom.com.br    | Brazil            | Rio de Janeiro     | Rio de Janeiro        | ALGAR TELECOM SA                              | 16735     |
| 193.122.94.68       |                                              | Saudi Arabia      | Eastern Province   |                       | ORACLE-BMC-31898                              | 31898     |
| 194.180.49.161      |                                              | Bulgaria          |                    |                       | MEVSPACE sp. z o.o.                          | 201814    |
| 20.235.247.188      |                                              | India             | Maharashtra        | Pune                  | MICROSOFT-CORP-MSN-AS-BLOCK                  | 8075      |
| 203.189.135.33      | mydsl-135-33.online.com.kh                   | Cambodia          | Phnom Penh         | Phnom Penh            | Cogetel Online, Cambodia, ISP                | 23673     |
| 206.189.208.53      | prod-beryllium-sfo2-51.do.binaryedge.ninja   | United States     | California         | Santa Clara           | DIGITALOCEAN-ASN                             | 14061     |
| 218.24.151.212      |                                              | China             | Liaoning           | Shenyang              | CHINA UNICOM China169 Backbone               | 4837      |
| 218.90.122.42       |                                              | China             | Shanghai           | Shanghai              | Chinanet                                     | 4134      |
| 31.43.185.66        |                                              | Ukraine           |                    |                       | FOP Dmytro Nedilskyi                          | 211736    |
| 36.134.25.206       |                                              | China             |                    |                       | China Mobile Communications Group Co., Ltd.  | 9808      |
| 79.124.56.98        | marathon.witud.us                            | Bulgaria          |                    |                       | Tamatiya EOOD                                | 50360     |
| 87.251.75.64        |                                              | Russia            |                    |                       | Xhost Internet Solutions Lp                  | 208091    |
| 92.255.57.161       |                                              | Hong Kong         |                    |                       | Chang Way Technologies Co. Limited           | 207566    |
| 94.102.49.171       | no-reverse-dns-configured.com                | The Netherlands   | North Holland      | Amsterdam             | IP Volume inc                                | 202425    |
| 94.232.42.99        |                                              | Russia            | Perm Krai          | Perm                  | Xhost Internet Solutions Lp                  | 208091    |
| 94.76.207.192       | 94-76-207-192.static.as29550.net             | United Kingdom    |                    |                       | Simply Transit Ltd                           | 29550     |

Just getting the ip's wasn't good enough for me - I wanted a visual display of the attacks on a world map & the charted out.

![image](https://github.com/user-attachments/assets/a1329c96-c20d-4f73-a2cc-d36df6ab5a4c)

![image](https://github.com/user-attachments/assets/a1b9e138-d593-4551-932d-8233eaee8bf7)

## 4. Temporal Trends
- By examining the timestamps in `TimeGenerated [UTC]` and `TimeCollected [UTC]` ( I converted them into my local time - EST), events can be analyzed for spikes in activity.
- Peaks in failed login attempts may align with specific times of day, suggesting targeted attacks during presumed off-hours.

Peak Activity: The highest number of events occurred at 12AM EST, with 774 recorded events.

Other Busy Periods:
1:00 AM EST (671 events)
2:00 AM EST (602 events)
12:00 AM EST (587 events)

![image](https://github.com/user-attachments/assets/6b28df34-e2c6-4784-ae90-29ee3f974ebf)

### Observations
- There is a noticeable increase in failed login attempts during the late afternoon to early evening UTC time (16:00–19:00), suggesting targeted activity during these hours.
These times could correlate to presumed "off-hours" for some geographic regions, indicating attackers might aim to exploit periods when monitoring is less rigorous.
---

# Lessons learned from this

## 1. Strengthening Account Security
- The prevalence of failed login attempts targeting admin-level accounts
  - Enforce strong password policies to prevent brute force attacks.
  - Implement multi-factor authentication (MFA) adding an extra layer of defense.

    (This was the password I opted to use for the VM & how fast it would take for attackers to crack it)
    
  ![image](https://github.com/user-attachments/assets/e65dffc5-db63-4a57-a79e-2ba215b6d859)

## 2. Improving Network Security
- Most logon attempts were of type `3 - Network`, which indicated a need to secure external access points:
  - The use of firewalls and geo-blocking to limit access from suspicious or unexpected locations is a good start.
  - Regularly update and patch systems to reduce vulnerabilities that attackers could exploit. Close any ports that put the machines at risk such as RDP, SSH, Etc.

## 3. Enhancing Monitoring and Logging
- The presence of log entries without IP addresses indicates gaps in monitoring:
  - Ensure comprehensive logging across all systems to maintain a full audit trail.
  - Use centralized log management tools to aggregate and analyze logs for quicker response times.

## 4. Proactive Detection
- Many failed logins suggest the need for further enhanced real time threat detection:
  - Implement intrusion detection and prevention systems (IDPS) to identify and block malicious attempts in real-time.
  - Use AI-powered log analytics to detect patterns indicative of coordinated attacks.
  - Role-Based Access Control: Restrict administrative privileges to reduce the number of high-value targets.

## 5. Response to Incidents
- Regular review of log data to help identify compromised accounts.
- Establish an incident response plan to address potential breaches detected through log analysis.

---

# Closing notes
This analysis I made revealed several key insights into potential security vulnerabilities and attack patterns. Frequent failed login attempts targeting privileged accounts, such as "Administrator" and "VMADMIN," highlighted the need for stronger access controls and more proactive monitoring. The diverse geographic sources of these attacks suggest a wide range of malicious actors, utilizing botnets or automated attack tools to conduct brute-force login attempts.

Events like the shutdown and startup of the event logging service, along with changes to system time, raised concerns about the potential tampering of logging mechanisms to evade detection. These findings underscore the importance of maintaining tamper-proof logging systems, which are critical for detecting and responding to attacks.

The analysis of privilege escalation attempts and user group enumerations revealed that attackers are likely conducting reconnaissance to gain higher-level access or escalate their privileges. The creation of new processes and cryptographic operations further suggests active exploitation or the presence of malware. These patterns emphasize the need for robust endpoint detection and response (EDR) solutions, as well as continuous monitoring of system processes and activities.

Temporal Trends indicated deliberate timing of attacks, with peaks in failed login attempts during obscure times, potentially exploiting presumed "off-hours" for monitoring. This highlighted the need for 24/7 monitoring and response capabilities, as well as the importance of time-based anomaly detection systems.

# Final Thoughts:
This lab provided valuable insights into how attackers probe cloud environments, especially focusing on weak login credentials, poor network security configurations, and lapses in monitoring. By improving security practices based on these findings—such as implementing stricter access controls, strengthening defenses against brute-force attacks, and continuously improving detection capabilities—you can significantly enhance the overall security posture of the infrastructure. The lessons learned from this lab are not just theoretical but can be directly applied to protect live environments from evolving cyber threats.
