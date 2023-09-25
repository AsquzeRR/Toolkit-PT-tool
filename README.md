# Package-Brute-Force-Tool
This toolkit is designed for educational purposes, helping students explore various aspects of cybersecurity. It enables you to:

    Enumerate and scan operating systems.
    Perform brute-force attacks on SSH and FTP services.
    Gain shell access upon successful credential discovery.
    Determine if an IP address is in use by another device on a local area network using the Ping ARP Tool.

Please remember that this toolkit should only be used for learning and educational purposes.


# Usage:

**Please follow this tips to install the toolkit:**

```git clone https://github.com/AsquzeRR/Toolkit-PT-tool.git```

```apt-get install python3-pip```

```pip3 install -r requirements.txt```

***libraries:***

>ftplib,
>socket,
>sys,
>datetime,
>requests,
>paramiko,
>pyfiglet,
>scapy,
>os,
>time,
>subprocess,

Package-Brute-force-Tool is a comprehensive package designed for penetration testing and network security assessment. It includes a range of useful tools and functionalities to assist cybersecurity professionals in conducting various tests and analyses. Here is a breakdown of the features included in the Toolkit-PT-tool package:

Check online IPs in network: This feature allows you to scan the network and identify active IP addresses that are currently online. It provides valuable information about the devices connected to the network.

Scan network or IP like Nmap: Similar to the popular network scanning tool Nmap, this feature enables you to perform comprehensive network scans. It helps identify open ports, services, and potential vulnerabilities in the target system or network.

Brute-Force on port 22: This feature specifically targets port 22, which is commonly used for SSH (Secure Shell) connections. It performs a brute-force attack, attempting to gain unauthorized access to the system by systematically trying different username and password combinations.

Brute-Force on port 21: This feature focuses on port 21, which is typically used for FTP (File Transfer Protocol) connections. It conducts a brute-force attack to discover weak or easily guessable credentials and gain unauthorized access to FTP servers.

Brute-Force For sites: This feature is designed for brute-forcing websites, allowing you to test the security of web applications by attempting to guess usernames and passwords or exploit weak authentication mechanisms.

Ping ARP: This feature performs an ARP (Address Resolution Protocol) ping sweep, which helps identify and map IP addresses to MAC addresses in the network. It aids in network reconnaissance and troubleshooting.

Ping ICMP: ICMP (Internet Control Message Protocol) ping is a network diagnostic tool used to check the connectivity and response time of a remote host. This feature allows you to send ICMP echo requests to specific IP addresses and analyze the responses.

MITM attack: MITM stands for Man-in-the-Middle, which is an attack technique where an attacker intercepts and alters communication between two parties. This feature enables you to simulate and analyze the impact of a MITM attack in a controlled environment.
