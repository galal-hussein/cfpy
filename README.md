# CloudFlare API V4 Python Wrapper

This is my first attempt to write python project, this wrapper covers most of the functions for cloudflare api V4 endoint:
```
https://api.cloudflare.com/client/v4
```
## Installation
Install the wrapper using pip:
```
# pip install cfpy
```
## Usage
Import the wrapper and add your "Auth Email" and "Auth key" as following:
```
from cfpy import CFapi
cf = cfapi('auth_mail', 'auth_key')
print cf.list_zones()
```

## Contribute

This wrapper covers the major functtions for the API but there are still endpoints that were not covered especially the functions for "Enterprise only", so please contribute to the repo by adding the missing functions.

The covered endpoints:

- User
- User Billing Profile
- App Subscription
- Zone Subscription
- User-level Firewall access rule
- Zone
- Zone Plan
- Zone Settings
- DNS Records for a Zone
- Railgun connections for a Zone
- Zone Analytics
- Railguns

The uncovered endpoints:

- User's Organizations
- User's Invites
- WAF related endpoints
- Organizations related endpoints
- User-level Firewall access rule