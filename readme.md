# Dreamhost DNS

This is a Python script for updating all your Dreamhost domain and subdomain names if you have a Dynamic DNS situation.

Run this script on whatever computer is hosting the DNS.

You will need a Dreamhost API key.

Create a settings.json file that looks like this:

```json
{
  "api_key": "myapikey",
  "domains": ["sub.domain1.com", "sub.domain2.com", "sub2.domain1.com"]
}
```
If you have requests installed on your system, you can just put the settings.json file next to your script and run it. 

If you run everything in a virtual environment, then create your venv and pip install -r requirements.txt

If you want to run via cron, your best bet is to create a bash script that will change to that directory, activate the venv, and run it.

