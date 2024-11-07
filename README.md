30-Days SOC Challenge

Day 1: Network Architecture Design for SOC Environment

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


Day 2: Elastic Stack

The Elastic stack known as the ELK stack has three core components that work to ingest, process, store, and visualize our data.

* Elastic Search at its core is a database to store logs such as Windows event logs, syslogs, and firewall logs. It provides the capability to search across your data. Elastic search also uses RESTful APIs & JSON. This means you can use various applications to 
  interact with your elastic search database in a programmable way to retrieve information as required. I will be using Cabana as an alternative.

* Log Stash collects Telemetry from various sources it also transforms filters and outputs them into elastic search instances. As a side note when collecting Telemetry, there are many ways to do this with two popular ways being Beats and elastic agents. There are 6 types 
   of Beats (Telemetry is the automated process of collecting and transmitting data from remote sources for monitoring and analysis)

* Kibana: Serves as the Web Gui, you can quickly search data, Create visualization, create Reports, create alerts, and build dashboards.


Day 3-4: Setup Elastic & Kibana Server

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
  * Under Firewall, assign the newly created 30-Day-MyDFIR-SOC-Challenge-CAG group to the VM.


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


Kibana Setup

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

    
