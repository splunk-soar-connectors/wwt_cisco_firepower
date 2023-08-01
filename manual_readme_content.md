[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2016-2022 Splunk Inc."
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
## Explanation of the Asset Configuration Parameters

Following is the explanation of asset configuration parameters.

-   **Device IP/Hostname:** The IP/Hostname of the Firepower Management Center instance.
-   **Verify server certificate:** Validate server certificate.
-   **User with access to the Firepower node:** Username of the user with access to the Firepower
    node.
-   **Password:** Password for the above mentioned username.
-   **Firepower Domain:** The Firepower domain you want to run the actions on.
-   **Network Group Object:** The network group object you want to run the actions on.

## Authentication

The app uses token-based authentication. The 'test connectivity' action fetches a new token in
exchange for the provided username and password. The app uses this token for authentication. The
newly fetched token is encrypted and stored in the state file for future use. If the stored token
expires or gets corrupted, the app automatically generates a new one.

## Port Information

The app uses HTTP/HTTPS protocol for communicating with the Cisco Firepower Server. Below are the
default ports used by Splunk SOAR.

| Service Name | Transport Protocol | Port |
|--------------|--------------------|------|
| http         | tcp                | 80   |
| https        | tcp                | 443  |
