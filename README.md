NodeDynDNS
==========

Motivation
----------
I was looking for a way to have a dynamic DNS service to my home router so I
could make a game server (ARK: Survival Evolved) easily accessible to non-CS
people. There already was a server I could use and after quickly searching for
dynamic DNS software I decided I could develop something with appropriate use
application of OOP myself. So I started this project


Project Summary
---------------
- JavaScript on node.js
- RFC 1035 compliant
- API with http basic authentication to update 


Setup Instructions
------------
- Have node.js installed
- run: npm install
- Rename conf.example.json to conf.json and make your settings (pretty self-explanatory)
- DO NOT enter the password in clear text. Instead call npm run hash. You will see what it does


Additional Notes
----------------
- Make sure you have the correct records DNS record set, so this DNS server will actually be accessed
- You can of course add multiple domains
- App must be run with root privileges to be able to bind to dns port 53/udp
- The app will drop privileges to user and group defined in the "system" dict
- If you want no http or https server just remove it from the config file
- The dot at the end of the of the domain IS REQUIRED
- The app will save the set records in storage.json
- DO NOT TOUCH storage.json, except if you want to set a specific init IP
- EXCEPT maybe to clear dns data, you can delete it


Running the app
---------------
- node .
