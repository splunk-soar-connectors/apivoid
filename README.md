[comment]: # "Auto-generated SOAR connector documentation"
# APIvoid

Publisher: Splunk  
Connector Version: 2\.0\.4  
Product Vendor: APIVoid  
Product Name: APIVoid  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.1\.0  

This app supports executing investigative and reputation actions on the URLVoid service

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a APIVoid asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**server\_url** |  required  | string | Server URL
**api\_key** |  required  | password | API Key

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[get cert info](#action-get-cert-info) - Queries certification info  
[domain reputation](#action-domain-reputation) - Queries domain info  
[ip reputation](#action-ip-reputation) - Queries IP info  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'get cert info'
Queries certification info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to query | string |  `domain`  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain`  `url` 
action\_result\.data\.\*\.credits\_expiration | string | 
action\_result\.data\.\*\.credits\_remained | numeric | 
action\_result\.data\.\*\.data\.certificate\.blacklisted | boolean | 
action\_result\.data\.\*\.data\.certificate\.debug\_message | string | 
action\_result\.data\.\*\.data\.certificate\.deprecated\_issuer | boolean | 
action\_result\.data\.\*\.data\.certificate\.details\.extensions\.authority\_info\_access | string | 
action\_result\.data\.\*\.data\.certificate\.details\.extensions\.authority\_key\_identifier | string | 
action\_result\.data\.\*\.data\.certificate\.details\.extensions\.basic\_constraints | string | 
action\_result\.data\.\*\.data\.certificate\.details\.extensions\.certificate\_policies | string | 
action\_result\.data\.\*\.data\.certificate\.details\.extensions\.crl\_distribution\_points | string | 
action\_result\.data\.\*\.data\.certificate\.details\.extensions\.extended\_key\_usage | string | 
action\_result\.data\.\*\.data\.certificate\.details\.extensions\.key\_usage | string | 
action\_result\.data\.\*\.data\.certificate\.details\.extensions\.subject\_key\_identifier | string | 
action\_result\.data\.\*\.data\.certificate\.details\.hash | string | 
action\_result\.data\.\*\.data\.certificate\.details\.issuer\.common\_name | string | 
action\_result\.data\.\*\.data\.certificate\.details\.issuer\.country | string | 
action\_result\.data\.\*\.data\.certificate\.details\.issuer\.location | string | 
action\_result\.data\.\*\.data\.certificate\.details\.issuer\.organization | string | 
action\_result\.data\.\*\.data\.certificate\.details\.issuer\.organization\_unit | string | 
action\_result\.data\.\*\.data\.certificate\.details\.issuer\.state | string | 
action\_result\.data\.\*\.data\.certificate\.details\.signature\.serial | string | 
action\_result\.data\.\*\.data\.certificate\.details\.signature\.serial\_hex | string |  `md5` 
action\_result\.data\.\*\.data\.certificate\.details\.signature\.type | string | 
action\_result\.data\.\*\.data\.certificate\.details\.subject\.alternative\_names | string | 
action\_result\.data\.\*\.data\.certificate\.details\.subject\.category | string | 
action\_result\.data\.\*\.data\.certificate\.details\.subject\.common\_name | string | 
action\_result\.data\.\*\.data\.certificate\.details\.subject\.country | string | 
action\_result\.data\.\*\.data\.certificate\.details\.subject\.location | string | 
action\_result\.data\.\*\.data\.certificate\.details\.subject\.name | string | 
action\_result\.data\.\*\.data\.certificate\.details\.subject\.organization | string | 
action\_result\.data\.\*\.data\.certificate\.details\.subject\.organization\_unit | string | 
action\_result\.data\.\*\.data\.certificate\.details\.subject\.postal\_code | string | 
action\_result\.data\.\*\.data\.certificate\.details\.subject\.state | string | 
action\_result\.data\.\*\.data\.certificate\.details\.subject\.street | string | 
action\_result\.data\.\*\.data\.certificate\.details\.validity\.days\_left | numeric | 
action\_result\.data\.\*\.data\.certificate\.details\.validity\.valid\_from | string | 
action\_result\.data\.\*\.data\.certificate\.details\.validity\.valid\_from\_timestamp | numeric | 
action\_result\.data\.\*\.data\.certificate\.details\.validity\.valid\_to | string | 
action\_result\.data\.\*\.data\.certificate\.details\.validity\.valid\_to\_timestamp | numeric | 
action\_result\.data\.\*\.data\.certificate\.details\.version | string | 
action\_result\.data\.\*\.data\.certificate\.expired | boolean | 
action\_result\.data\.\*\.data\.certificate\.fingerprint | string |  `sha1` 
action\_result\.data\.\*\.data\.certificate\.found | boolean | 
action\_result\.data\.\*\.data\.certificate\.name\_match | boolean | 
action\_result\.data\.\*\.data\.certificate\.valid | boolean | 
action\_result\.data\.\*\.data\.certificate\.valid\_peer | boolean | 
action\_result\.data\.\*\.data\.host | string | 
action\_result\.data\.\*\.elapsed\_time | string | 
action\_result\.data\.\*\.estimated\_queries | string | 
action\_result\.data\.\*\.success | boolean | 
action\_result\.summary\.certificate\_found | boolean | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'domain reputation'
Queries domain info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to query | string |  `domain`  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain`  `url` 
action\_result\.data\.\*\.alexa\_top\_100k | boolean | 
action\_result\.data\.\*\.alexa\_top\_10k | boolean | 
action\_result\.data\.\*\.alexa\_top\_250k | boolean | 
action\_result\.data\.\*\.detection\_rate | string | 
action\_result\.data\.\*\.detections | numeric | 
action\_result\.data\.\*\.domain\_length | numeric | 
action\_result\.data\.\*\.engines\.\*\.confidence | string | 
action\_result\.data\.\*\.engines\.\*\.detected | boolean | 
action\_result\.data\.\*\.engines\.\*\.elapsed | string | 
action\_result\.data\.\*\.engines\.\*\.engine | string | 
action\_result\.data\.\*\.engines\.\*\.reference | string |  `url` 
action\_result\.data\.\*\.engines\_count | numeric | 
action\_result\.data\.\*\.most\_abused\_tld | boolean | 
action\_result\.data\.\*\.scantime | string | 
action\_result\.summary\.detections | numeric | 
action\_result\.summary\.engines\_count | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'ip reputation'
Queries IP info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to query | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.data\.\*\.detection\_rate | string | 
action\_result\.data\.\*\.detections | numeric | 
action\_result\.data\.\*\.engines\.\*\.detected | boolean | 
action\_result\.data\.\*\.engines\.\*\.elapsed | string | 
action\_result\.data\.\*\.engines\.\*\.engine | string | 
action\_result\.data\.\*\.engines\.\*\.reference | string |  `url` 
action\_result\.data\.\*\.engines\_count | numeric | 
action\_result\.data\.\*\.scantime | string | 
action\_result\.summary\.detections | numeric | 
action\_result\.summary\.engines\_count | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 