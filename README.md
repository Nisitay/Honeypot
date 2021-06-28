# Honeyroute
Honeyroute is a honeypot written in Python, and it's configured for routing (in a concealed manner) various attacks to a dedicated honeypot machine,
without being detected by the attacker. In other words, the attacker will believe his attack worked, but in reality he got fake information.

Honeyroute can detect and defend against the following attacks:
- SYN Flood - Blocks attackers and convinces them that the attack has succeeded, while still communicating with legit clients.
- SQL Injection - Routes the request to the honeypot, and returns data from a fake database.
- Anonymous FTP Session - Routes FTP commands & data to the honeypot so fake and dangerous files/folders don't appear on the asset

## Usage
To run the main application:

    $ python -m Honeypot.main

Honeyroute also includes a PowerShell script to automatically install the Windows feature for IIS Management, and start an FTP server configured to accept
anonymous users. To run the script, simply run the `run_ftp.bat` file.

## Screenshots
- The GUI was written with PyQt5 and QML

### Log & Routers
![log and routers](https://github.com/Nisitay/Honeypot/blob/master/Screenshots/1.png)

### Blacklist Management & Statistics
![blacklist and statistics](https://github.com/Nisitay/Honeypot/blob/master/Screenshots/2.png)

## How Does It Work?
Honeyroute uses `PyDivert` to catch packets before they reach their destination. The diverted packets are then handeled according to the protocol (FTP/HTTP)

### SYN Flood Detection & Defense
Honeyroute uses a dictionary to store the number of SYN packets sent from a specific address. Once the number of packets exceeds the allowed amount,
Honeyroute defends against it - a new `pydivert` handle is started with higher priority than the main handle, and it catches the packets from the attacking address
for ~30 seconds.

### SQL Injection Detection & Defense
The web server on the honeypot machine is intentionally vulnerable to SQL injection - when a user wants to log into an account, the server takes the first user that matches the following query:
```python
'SELECT * FROM User WHERE email = "' + form.email.data + '" AND password  = "' + form.password.data + '"'
```
Therefore, by entering the expression `" or ""="` the query will always be true, and the attacker will be logged into the first fake user in the database.

Honeyroute searches for the `"` and `'` characters in the HTTP payload used to login.
If those characters appear, it routes the request to the honeypot and returns the fake user data to the attacker. 

### FTP Anonymous Session Detection & Defense
The IIS FTP server on the honeypot intentionally allows sessions from anonymous users. 
While this behavior can work in certain circumstances, it can result in many attacks targeting the file system.

To allow attacks on the honeypot, as well as normal usage of the asset FTP server, Honeyroute "whitelists" some passwords of legit users.
Honeyroute then examines every login attempt to the asset, and if an attacker enters a non-whitelisted password,
the session is routed to the honeypot.
Even though FTP uses 2 TCP sessions (a command channel and a data channel) Honeyroute supports the main FTP functionalities:
file/folder upload & download, file/folder deletion etc.   

## Authors
- **Itay Margolin** - [Nisitay](https://github.com/Nisitay)