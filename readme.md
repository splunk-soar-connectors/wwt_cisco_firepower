[comment]: # "Auto-generated SOAR connector documentation"
# Cisco Firepower

Publisher: World Wide Technology  
Connector Version: 1\.2\.3  
Product Vendor: Cisco Systems  
Product Name: Cisco Firepower  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 3\.0\.264  

This app interfaces with Cisco Firepower devices to add or remove IPs or networks to a Firepower Network Group Object, which is configured with an ACL

Cisco Firepower

Publisher: World Wide Technology
App Version: 1.1.8
Product Vendor: Cisco Systems
Product Name: Cisco Firepower
Product Version Supported (regex): ".*"
This app interfaces with Cisco Firepower devices to add or remove IP's or
networks to a Firepower Network Group Object, which is configured with an ACL

Configuration Variables

The below configuration variables are required for this App to operate on Cisco
Firepower. These are specified when configuring an asset in Phantom.

VARIABLE    REQUIRED    TYPE    DESCRIPTION
username    required    string    User with access to the Firepower node
network_group_object    required    string    Network Group Object
domain_name    required    string    Firepower Domain
firepower_host    required    string    Device IP/Hostname
password    required    password    Password
Supported Actions

test connectivity - Validate the asset configuration for connectivity
list networks in object - Lists currently blocked networks
block ip - Blocks an IP network
unblock ip - Unblocks an IP network
action: 'test connectivity'

Validate the asset configuration for connectivity

Type: test

Read only: True

This action logs into the Cisco Firepower device using a REST call

Action Parameters

No parameters are required for this action

Action Output

No Output

action: 'list networks in object'

Lists currently blocked networks

Type: investigate

Read only: True

Action Parameters

No parameters are required for this action

Action Output

DATA PATH    TYPE    CONTAINS
action_result.data.*.network    string    
action_result.status    string    
action_result.message    string    
action: 'block ip'

Blocks an IP network

Type: contain

Read only: True

Action Parameters

PARAMETER    REQUIRED    DESCRIPTION    TYPE    CONTAINS
destination_network    required    IP/network to block (X.X.X.X/NM)    string    
Action Output

No Output

action: 'unblock ip'

Unblocks an IP network

Type: correct

Read only: True

Action Parameters

PARAMETER    REQUIRED    DESCRIPTION    TYPE    CONTAINS
destination_network    required    IP/network to unBlock (X.X.X.X/NM)    string    
Action Output

No Output


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