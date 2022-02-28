[comment]: # "Auto-generated SOAR connector documentation"
# Cisco Firepower

Publisher: World Wide Technology  
Connector Version: 1\.2\.3  
Product Vendor: Cisco Systems  
Product Name: Cisco Firepower  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 3\.0\.264  

[comment]: # "    File: readme.md"
[comment]: # "    Copyright (c) 2016-2022 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""

This app interfaces with Cisco Firepower devices to add or remove IPs or networks to a Firepower Network Group Object, which is configured with an ACL

**Playbook Backward Compatibility**

One new asset parameter has been added to the asset configuration given below. Hence, it is requested to the end-user please update their existing playbooks and provide values to this new parameter to ensure the correct functioning of the playbooks created on the earlier versions of the app.

*   **For version 1.3.X :**

    *   Test Connectivity - **port** parameter has been added

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Cisco Firepower server. Below are the
default ports used by Splunk SOAR.

|         SERVICE NAME | TRANSPORT PROTOCOL | PORT |
|----------------------|--------------------|------|
|         http         | tcp                | 80   |
|         https        | tcp                | 443  |
### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Cisco Firepower asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**firepower\_host** |  required  | string | Device IP/Hostname
**username** |  required  | string | User with access to the Firepower node
**password** |  required  | password | Password
**domain\_name** |  required  | string | Firepower Domain
**network\_group\_object** |  required  | string | Network Group Object

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity  
[list networks](#action-list-networks) - Lists currently blocked networks  
[block ip](#action-block-ip) - Blocks an IP network  
[unblock ip](#action-unblock-ip) - Unblocks an IP network  

## action: 'test connectivity'
Validate the asset configuration for connectivity

Type: **test**  
Read only: **True**

This action logs into the Cisco Firepower device using a REST call

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'list networks'
Lists currently blocked networks

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.network | string | 
action\_result\.status | string | 
action\_result\.message | string |   

## action: 'block ip'
Blocks an IP network

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP/network to block \(X\.X\.X\.X/NM\) | string |  `ip`  `ip network` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.ip | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'unblock ip'
Unblocks an IP network

Type: **correct**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP/network to unBlock \(X\.X\.X\.X/NM\) | string |  `ip`  `ip network` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.ip | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 

## action: 'get signature details'
Get detailed information about a signature

Type: **investigate**  
Read only: **True**

One of the <b>snort\_id</b>, <b>bugtraq\_id</b> or <b>svid</b> parameters need to be specified\. The action will first check for the presence of an id to use it and ignore the rest in the following order\: <ul><li><b>snort\_id</b><br>The action will use this id if specified and ignore the rest while making the query\.</li><li><b>bugtraq\_id</b><br>If snort\_id is not passed, the action will use the bugtraq\_id for the query if specified\.</li><li><b>svid</b><br>If both snort\_id and bugtraq\_id are not specified, the action proceeds to check the presence of the svid and uses it for the query\.</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**snort\_id** |  optional  | Snort ID | string |  `snort id` 
**bugtraq\_id** |  optional  | Bugtraq ID | string |  `bugtraq id` 
**svid** |  optional  | Sourcefire Vuln ID | string |  `sourcefire vuln id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.snort\_id | numeric |  `snort id` 
action\_result\.data\.\*\.title | string | 
action\_result\.data\.\*\.rna\_vuln\_id | numeric |  `sourcefire vuln id` 
action\_result\.data\.\*\.bugtraq\_id | numeric |  `bugtraq id` 
action\_result\.data\.\*\.available\_exploits | string | 
action\_result\.data\.\*\.remote | string | 
action\_result\.data\.\*\.exploit | string | 
action\_result\.data\.\*\.short\_description | string | 
action\_result\.status | string | 
action\_result\.summary\.total\_signatures | numeric | 
action\_result\.parameter\.snort\_id | string |  `snort id` 
action\_result\.parameter\.bugtraq\_id | string |  `bugtraq id` 
action\_result\.parameter\.svid | string |  `sourcefire vuln id` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 