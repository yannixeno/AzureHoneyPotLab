# Azure Sentinel Honeypot Lab
![winnie-the-pooh-pooh](https://github.com/user-attachments/assets/64bc52e5-92bc-4800-ac5f-946360d274c8)

## Objective
The Detection Lab project aimed to establish a controlled environment for monitoring and analyzing live cyber attacks occurring globally. The primary focus was to ingest and analyze logs within a Security Information and Event Management (SIEM) system, providing insights into real-world attack patterns and enhancing defensive strategies. This project aims to develop practical skills in cloud security, ensuring that the configured systems effectively detect and respond to potential threats. Ultimately, the objective is to validate the security configurations through testing, ensuring a robust security posture in a cloud environment.

## Skills Learned
- Advanced understanding of SIEM concepts and practical application.
- Proficiency in analyzing and interpreting logs.
- Ability to generate and recognize attack signatures and patterns.
- Enhanced knowledge of network protocols and security vulnerabilities.
- Development of critical thinking and problem-solving skills in security.

## Steps

### Step 1: Set Up an Azure Free Trial
- Navigate to Azure and set up a free trial.
- Sign up and verify your account—you’ll receive $200 in free credits.
- Provide necessary personal information to complete registration.

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
  - Select "Honeypott VM" as the resource and choose "All Security Events."

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


    ![image](https://github.com/user-attachments/assets/64d84a28-caf1-436a-94c5-81f869c59604)


### Step 6: Test and Verify Sentinel Alerts
- Check the Analytics page for the new rule you created.
- Monitor the Incidents page to see if a new alert appears.
- Confirm that the rule captures successful login events and generates alerts accordingly.





![image](https://github.com/user-attachments/assets/926fe3aa-950b-4e4c-b316-0956b1ed9d7b)

![image](https://github.com/user-attachments/assets/8272dea4-6d48-4ab5-a1e5-582f2e79dba1)

![image](https://github.com/user-attachments/assets/30b1dba8-3394-4dab-b9b3-e02814de7f22)


