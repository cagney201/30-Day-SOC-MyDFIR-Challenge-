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

* Elastic Search at its core is a database to store logs such as windows event logs, syslogs, and firewall logs. It provides the capability to search across your data. Elastic search also uses RESTful APIs & JSON. This means you can use various applications to 
  interact with your elastic search database in a programmable way to retrieve information as required. I will be using Cabana as an alternative.

* Log Stash collects Telemetry from various sources it also transforms filters and outputs it into elastic search instances. As a side note when collecting Telemetry, there are many ways to do this with two popular ways being Beats and elastic agents. There are 6 types of 
  Elastic Beats (Telemetry is the automated process of collecting and transmitting data from remote sources for monitoring and analysis)

* Kibana: Serves as the Web Gui, you can quickly search data, Create visualization, create Reports, create alerts, and build dashboards.
