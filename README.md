30-Days SOC Challenge

**Day 1: Network Architecture Design for SOC Environment**

 I designed a network architecture diagram to set up a secure SOC environment for testing and monitoring. Using Draw.io, I created a visual layout that organizes the infrastructure into a cloud-based environment hosted on Vultr, with one on-premise machine for attack simulations.




![image](https://github.com/user-attachments/assets/48f2eddb-f650-4c51-bcc7-d2306bce9a39)


Network Architecture Details

The SOC environment comprises six servers, each serving distinct purposes, all hosted on Vultr’s cloud infrastructure within a Virtual Private Cloud (VPC). An internet gateway allows connection to my ISP. I also have a kali attack Workstation hosted on-premises on my lab computer at home.

* Elastic & Kibana Server:  Collects and visualizes logs from other systems for real-time monitoring and threat detection
* Ubuntu Server:  SSH enabled for secure shell access, used for secure administration and task automation
* Windows Server: RDP enabled for remote desktop sessions
* Fleet Server: Deploys and monitors agents installed on Elastic endpoints, supporting seamless configuration updates and data collection
* OsTicket Server: Centralized tracking and management of issues within the SOC, improving workflow and accountability
* Command & Control (C2) ServerCommand & Control (C2) Server: Hosts Mythic for running command-and-control (C2) operations, used for red-teaming and controlled testing of SOC defenses.
* Attacker Machine: Location: On-premise desktop setup in my home. Simulates an attacker’s machine to test the SOC’s defenses


**Day 2: Elastic Stack**

The Elastic stack known as the ELK stack has three core components that work to ingest, process, store, and visualize our data.

* Elastic Search at its core is a database to store logs such as Windows event logs, syslogs, and firewall logs. It provides the capability to search across your data. Elastic search also uses RESTful APIs & JSON. This means you can use various applications to 
  interact with your elastic search database in a programmable way to retrieve information as required. I will be using Cabana as an alternative.

* Log Stash collects Telemetry from various sources it also transforms filters and outputs them into elastic search instances. As a side note when collecting Telemetry, there are many ways to do this with two popular ways being Beats and elastic agents. There are 6 types 
   of Beats (Telemetry is the automated process of collecting and transmitting data from remote sources for monitoring and analysis)

* Kibana: Serves as the Web Gui, you can quickly search data, Create visualization, create Reports, create alerts, and build dashboards.


**Day 3-4: Setup Elastic & Kibana Server**

1. Vultr settings 
 * Login to the Vutur website navigate to the network option select VPC 2.0 & use the 172.31.0.0/24 for our private network
 * Deploy a new server using Ubuntu 22.04 with 80 GB with 4 virtual CPUs 16 GB, unselect auto backups & IPv6
 * Server hostname will be MYDFIR-ELK-CAG
   Deploy now

2. Installing Elastic Server
 * Open PowerShell and SSH into the server

 * Let's update our repositories with the following command
 
   ```powershell
   apt-get update && apt-get upgrade –y
   ```


 * log into the elastic website and select deb x86_64 https://www.elastic.co/downloads/elasticsearch right-click the download button and select copy link address
 * In the terminal type the following command to download the install file to our ELK server:
   ```powershell
   wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.15.3-amd64.deb
   ```
 * Next command will now install Elastic:
   ```powershell
   dpkg -i elasticsearch-8.15.0-amd64.deb
   ```
 
 * After installation, check the security auto-configuration details to find the superuser password. Copy and paste this information into a password manager for 
  safekeeping. If you need to reset the password for the built-in elastic superuser, you can do so by navigating to /usr/share/elasticsearch/bin/
   
 
3. Network configuration & Firewall settings

   Navigate to the elastic configuration file (elasticsearch.yml) which is located in this directory /etc/elasticsearch/
   Edit the elasticsearch.yml File
 
 * Open the elasticsearch.yml file using nano.
 Remove the comment symbol (#) before network.host and replace the value with your server's public IP address.
 Remove the # before http.port and set it to 9200 to enable HTTP access on the default port.

![image](https://github.com/user-attachments/assets/9ebdf921-6f9e-4ef3-a32b-0a294c1792cb)



4. Set Up a Firewall for Network Security

Purpose: We want to restrict access to the Elasticsearch server and prevent it from being exposed to the entire internet.

 * Go to your Virtual Private Cloud (VPC) settings and create a new firewall rule:
   Under Firewall settings, select Manage and then Add Firewall Group.
   Name the group: 30-Day-MyDFIR-SOC-Challenge-CAG
   <img width="791" alt="Screenshot 2024-11-06 at 5 52 29 PM" src="https://github.com/user-attachments/assets/37255208-471c-4bd1-933a-af2dfcb5c5f4">

Configure Inbound SSH Access
  
  * Modify the Inbound IPv4 rules for SSH:
  * Change the source to My IP to limit SSH access to only your local machine.
  * Assign the Firewall Group to Your VM

Navigate to the Compute section in your cloud provider's dashboard.
  * Select your Virtual Machine (VM), then go to Settings.
  * Under the Firewall, assign the newly created 30-Day-MyDFIR-SOC-Challenge-CAG group to the VM.


5. Start and Enable Elasticsearch Services
   * Reload systemd to apply any changes:
 ```bash
 sudo systemctl daemon-reload
 ```

  * Enable Elasticsearch to start automatically at boot time:

 ```bash
 sudo systemctl enable elasticsearch.service
 ```

  *  Start the Elasticsearch service:
 ```bash
 sudo systemctl start elasticsearch.service
 ```

* Check the status of the service to ensure it’s running:

```bash
sudo systemctl status elasticsearch.service
```

![Elasticsearch service status](https://github.com/user-attachments/assets/613b46a1-7ec3-46ac-8237-8cca4c59b1f1)


**Kibana Setup**

1. Download Kibana: https://www.elastic.co/downloads/kibana select DEBx86_64 and right click on the download button field and choose the copy link address

2. Kibana Configuration: After downloading Kibana we need to edit the configuration file like Elastic. nano /etc/kibana/kibana.yml
    
    * Server Port: Default port for Kibana (5601)
    * Server Host: is set to the public IP address of my server

  * I restarted my Kibana Service and made sure it was active:

    ![Kibana service status](https://github.com/user-attachments/assets/c8aff831-a63a-4e25-87ab-36fa0ab62760)



3. Enrollment Token: To connect Kibana to Elasticsearch I need to create an enrollment token.

    * Navigate to the bin directory of Elastic
      ```bash
      cd /usr/share/elasticsearch/bin
      ```
    * To generate a token use the following command:
      ```bash
      ./elasticsearch-create-enrollment-token --scope kibana
      ```

4. I had issues connecting to Kibana in my web browser, so I had to edit my firewall settings and allow any TCP ports from 1-65535 from my SOC analyst laptop
     * I also needed to allow port 5601 on my ELK server as well by running this command
       ```bash
       ufw allow 5601
       ```


**Day 5 Windows Server 2022 (RDP) install**

  I started by deploying a new server, opting for the "Cloud Compute - Shared CPU" configuration. I selected the same data center location as my Elastic server and used the "Windows Standard 2022" image.
    * To improve security, I updated my network diagram so that both the Windows and Ubuntu servers are positioned outside the Virtual Private Cloud (VPC). This setup creates a layer of protection, ensuring that if either of these servers is compromised, it 
       won’t expose critical systems like the Fleet Server, Elastic & Kibana, or the OS Ticket system

      
![image](https://github.com/user-attachments/assets/440fa212-dc92-4a0e-acbc-00ab5d9c5851)


**Day 6 Fleet Server**


Elastic Agent
Definition:
An Elastic Agent is a unified, lightweight agent that runs on your servers or endpoints (like workstations, cloud instances, etc.) to collect data and send it to Elasticsearch. It’s part of the Elastic Stack, which includes tools like Elasticsearch, Kibana, Beats, and Logstash.

The Elastic Agent simplifies the process of data collection. Instead of managing multiple agents for different types of data (e.g., one for logs, one for metrics, one for security), the Elastic Agent combines all of these into a single, unified agent.

Key Features:
Unified agent: Collects logs, metrics, security data, and more.
Centralized management: Elastic Agents can be centrally managed through Kibana, making it easier to deploy and configure.
Flexible and scalable: Works across various environments (on-prem, cloud, hybrid).

Fleet Server

Definition:
  A Fleet Server acts as the central management hub for Elastic Agents. It communicates with Elastic Agents, giving them configuration instructions and receiving the data they 
  collect. Fleet Server runs within your Elastic Stack environment and helps manage large numbers of Elastic Agents, providing a central point for their coordination and control.

Fleet Server is responsible for:

 * Enrolling Elastic Agents into your Fleet management system.
 * Pushing configurations to Elastic Agents.
 * Ensuring Elastic Agents are properly sending their data to Elasticsearch or Logstash.
 * Centralizing monitoring and management.


Analogy:
Imagine you're managing a fleet of delivery trucks (Elastic Agents) that carry packages (data) to various destinations (Elasticsearch).

* The Elastic Agents are like the trucks that are physically carrying the packages. Each truck is equipped to handle multiple types of deliveries (logs, metrics, etc.). They travel between different locations (servers/endpoints) to pick up and deliver packages (data).

* The Fleet Server is like the central logistics hub that manages all the trucks. This hub provides the trucks with the necessary instructions, routes, and schedules. It ensures the trucks are loaded with the right packages, sends updates on the routes, and monitors their progress. If any truck breaks down or deviates from its route, the logistics hub can take action to resolve the issue.

In short: Elastic Agent = Delivery truck (data collector)  Fleet Server = Central logistics hub (management and coordination)




**Day 7** How to set up Fleet server & Elastic agent:

The objective for today is to install the elastic agent on Windows server and enroll the Windows server into a fleet server

1. I clicked on "Deploy New Server" and selected the same city as my previous setup. For the operating system, I chose Ubuntu 22.04 and connected the server to the VPC network I had 
   created earlier, using VPC 2.0

2. I went to Fleet under Management in the Elastic Management Console. Then, I clicked Add Fleet Server and selected Quick Start. For the Host URL, I entered the public IP address of 
   the Fleet Server.

   * Add the public IP address of the fleet server and allow all TCP ports 1-65535 into the Firewall group
   * On the ELK server allow port number 9200 on the firewall  ufw allow 9200 (elastic search listens on this default port)

   

![image](https://github.com/user-attachments/assets/5ad3f250-48f6-46da-a4cc-b7f63cb11618)

3. SSH into our fleet server & update the repository

   * I copied the installation command for the Elastic Agent and pasted it into the Fleet Server terminal to initiate the installation 
     process. You should see "successfully enrolled  
     the Elastic Agent".

    * For our Elastic agents to communicate to our Fleet server we need to allow port 8220
      ```bash
      ufw allow 8220
      ```
    * Under the Fleet server settings change the host URL to port 8220, not 443
  
     ![image](https://github.com/user-attachments/assets/259e0a67-b0f3-49c0-8c79-a74c0e9d0fed)

  
      
     

4. Elastic Agent

   * I created a Fleet Server Policy policy and copied the Windows installation command to use later on the Windows Server.

![image](https://github.com/user-attachments/assets/2f71ce92-201d-43c1-8683-c35f5906bb28) 

   * I ran the installation command for the Elastic Agent and pasted it into the Fleet Server terminal to initiate the installation. I 
     added the --insecure flag at the end of the command since I didn't have a certificate authority. The agent installed successfully.
   * I can see my Windows server added as an agent.
![image](https://github.com/user-attachments/assets/04dec01a-1d2e-40b1-bb04-e08380e67f21)



**Day 8-9 Sysmom**


Sysmon, or System Monitor, is a Windows system service and driver that is part of the Sysinternals suite by Microsoft. Sysmon enhances the ability to monitor and log detailed system activity on a Windows machine, which is especially useful for threat detection, security incident response, and forensic investigations.

Key Features of Sysmon:
Process Creation Logging: 
Logs detailed information about each process that starts on the system, including command line arguments, process IDs, and parent processes.
Network Connections: Captures details about network connections made by monitored processes, including source and destination IP addresses and ports.
File Creation: Monitors and logs the creation of files, tracking changes to files and directories, which helps detect potential malware activity.

Registry Events: Tracks changes to the Windows Registry, often a key area affected by malware and unauthorized software.
Hashes: Allows the generation and storage of cryptographic hashes of files for verification and comparison, helping detect unauthorized changes or malicious files.
Use Cases in Cybersecurity:

Sysmon is commonly deployed in SOC (Security Operations Center) environments to enhance visibility into system activities and provide critical insights for identifying unusual behavior. By combining Sysmon logs with SIEM (Security Information and Event Management) tools, analysts can detect suspicious patterns like unauthorized logins, process injections, or data exfiltration attempts.


Additional Sysmon Event Types:

- **Event ID 6**: Monitors driver loading, which helps detect potentially malicious drivers that might be loaded onto the system.
- **Event ID 7**: Logs image loading, showing the libraries and DLLs that processes are loading, which aids in tracking potential malware components.
- **Event ID 8**: Detects remote thread creation, a method often used in malicious code injection attacks, signaling possible unauthorized code execution.
- **Event ID 10**: Monitors process access, logging when one process interacts with another—often an indicator of malicious activity like privilege escalation.
- **Event ID 22**: Captures DNS queries, providing insight into unusual domain lookups that may indicate command-and-control (C2) activity, useful for detecting malware or phishing-related threats.
  


**Sysmon Installation**

* RDP into my Windows server MYDFIR-WIN-CAG
* Download https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon & extract the zip file
* We will be using a popular Sysmon configuration file from the repository from Github https://raw.githubusercontent.com/olafhartong/sysmon-modular/refs/heads/master/sysmonconfig.xml
* Save the raw xml file and place it in the Sysmon folder
  ![image](https://github.com/user-attachments/assets/9135da08-7e59-41dd-af25-f2feb382d666)

* Open up PowerShell and copy and paste the sysmon file location & paste it in the terminal & run the following commands

```bash
.\Sysmon64.exe
.\Sysmon64.exe -i sysmonconfig.xml
```

* Veryfiy the sysmon ***services*** are running and the sysmon logs are being generated ***event viewer*** 
  
![image](https://github.com/user-attachments/assets/a0cefc4f-4927-493b-a9fe-eef51615558e)


**Day 10 Ingesting Data with ElasticSearch**


 * I navigated to the Elasticsearch homepage and clicked on "Add integrations."
 * Select ***Custom Windows Event Logs***
 * For the channel name I entered ***Microsoft-Windows_sysmon/Operational*** Which is found by opening Windows Server EventViewer, navigating to Sysmon, and right-clicking on Operational properties.
 * Set up an additional integration specifically for **Windows Defender logs**.
 * Found the channel name by going to the Event Viewer, selecting Windows Defender, right-clicking Operational, and clicking on Properties
 * To reduce the number of informational logs, I selected event IDs 116, 117, and 5001. In the advanced settings, I entered these event IDs and added the integration to the policy
 * Restart the Elastic Agent service on the Windows Server.
 * After making these configurations, Sysmon logs successfully appeared in Elasticsearch




![image](https://github.com/user-attachments/assets/c45a109f-452a-4906-a732-23bd85ee13ff)



![image](https://github.com/user-attachments/assets/7b526651-123d-4afd-a089-8159f55ffb81)



**Day 11: Brute Force Attack**


What is a brute force attack?

A person’s hands are shown typing on a laptop keyboard, overlaid with icons symbolizing various aspects of technology and cybersecurity. These include a central lock symbol, a desktop computer, a mobile device, an email envelope, a speech bubble, and a house with a shield
FacebookTwitterLinkedInPinterestEmailShare
Brute force attacks, used by hackers to gain unauthorized access and compromise networks, pose severe risks to companies’ data security. The process begins by selecting a target and then using automated software to test various combinations of passwords or keys. To break it down, these attacks are like a relentless locksmith trying thousands of keys, hoping to find the one that unlocks your front door. They use trial and error to guess or crack an account password, login credentials, and encryption keys. Source: https://blog.lumen.com/what-is-a-brute-force-attack/


![image](https://github.com/user-attachments/assets/04d595ee-ee6e-4c91-8731-7e5e553a6e24)


**Day 12 Ubuntu Server SSH enable installation**

  * Deploy New Server
  * Select **cloud compute-shared CPU**
  * Ubuntu 24.04 image
  * SSH from SOC laptop into the new server.
  * Check the **auth.log files to see if there were any failed login attempts to the server.
  * Watch the video below as I show you how I filter out the logs
  * To view the failed logins navigate to cd /var/log
  * cat auth.log
  * run command

     ```bash
    grep -i failed auth.log
    ```
    How to filter out to only display the IP addresses of users attempting to use the root command (IP address is the 9th delimiter)

    grep -i failed auth.log | grep -i root | cut -d ' ' -f 9

   ![image](https://github.com/user-attachments/assets/5a3b38b6-1e5c-49b7-a7c4-4eb792bb015f)




    
   
   
    

**Day 13 Install Elastic Agent on Linux Ubuntu SSH Server**

 * I created a Fleet Server policy (MYDFIR-LINUX-POLICY-CAG) for my Ubuntu Server & installed the Elastic agent on it.

   ![image](https://github.com/user-attachments/assets/92e1e1ea-2e58-44a7-b77a-112b0db6606c)



**Day 14: Creating Alerts and Dashboard in Kibana**

 * Accessed Elastic and navigated to the Discover section.
 * A filter was applied to display results exclusively for the Ubuntu server agent.
 * Added the following fields as columns:
   system.auth.ssh.event
   user.name
   source.ip

(The results were refined to show only failed SSH attempts.)

Saved this filtered view under the name **SSH Failed Activity**.

![image](https://github.com/user-attachments/assets/b701b312-76a4-4419-8d78-93a857739914)

 * From this saved query I created a new rule and named it **SSH Brute Force Activity**.
 * The alert is set to 5 failed login attempts within 5 minutes.
 * Next I created a map to search for the following:
   system.auth.ssh.event:* and agent.name:"MYDFIR-Linux-CAG" and system.auth.ssh.event:"Failed"
 * Saved the visualization
 *  I duplicated the new map and displayed both failed and accepted attempts.


   ![image](https://github.com/user-attachments/assets/a838a962-0198-4b29-adc4-34663707b5f5)











  





     
     






   




       
         



       

    
