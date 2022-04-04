# File: cisco_firepower_connector.py
#
# Copyright (c) 2016-2022 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

import phantom.app as phantom
import requests
import simplejson as json
from netaddr import IPNetwork
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from cisco_firepower_consts import *


class FP_Connector(BaseConnector):

    def __init__(self):
        """
        Instance variables
        """
        # Call the BaseConnectors init first
        super(FP_Connector, self).__init__()

        self.username = ""
        self.password = ""
        self.firepower_host = ""
        self.firepower_devices = []
        self.firepower_deployable_devices = []
        self.network_group_object = ""
        self.domain_name = ""
        self.destination_network = ""
        self.destination_dict = {}
        self.token = ""
        self.api_path = ""
        self.network_group_list = []
        self.domain_uuid = ""
        self.netgroup_uuid = ""
        self.headers = HEADERS
        self.verify = False
        self.nothing_to_deploy = False

    def initialize(self):
        """
        This is an optional function that can be implemented by the
        AppConnector derived class. Since the configuration dictionary
        is already validated by the time this function is called,
        it's a good place to do any extra initialization of any internal
        modules. This function MUST return a value of either
        phantom.APP_SUCCESS or phantom.APP_ERROR.  If this function
        returns phantom.APP_ERROR, then AppConnector::handle_action
        will not get called.
        """
        config = self.get_config()
        self._state = self.load_state()

        if not isinstance(self._state, dict):
            self.debug_print("Resetting the state file with the default format")
            self._state = {"app_version": self.get_app_json().get("app_version")}
            return self.set_status(phantom.APP_ERROR, STATE_FILE_CORRUPT_ERR)

        self.firepower_host = config["firepower_host"]
        self.username = config["username"]
        self.password = config["password"]
        self.domain_name = config["domain_name"]
        self.network_group_object = config["network_group_object"]

        force = True if self.get_action_identifier() == "test connectivity" else False
        ret_val = self._get_token(self, force=force)
        if phantom.is_fail(ret_val):
            return self.get_status()

        ret_val = self._get_group_object_uuid()
        if phantom.is_fail(ret_val):
            return self.get_status()

        return phantom.APP_SUCCESS

    def finalize(self):
        """
        This function gets called once all the param dictionary
        elements are looped over and no more handle_action calls are
        left to be made. It gives the AppConnector a chance to loop
        through all the results that were accumulated by multiple
        handle_action function calls and create any summary if
        required. Another usage is cleanup, disconnect from remote
        devices etc.
        """
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _get_group_object_uuid(self):
        """
        This method is responsible for getting the UUID associated with
        the network group object specified in the app config and setting
        the netgroup_uuid variable.
        """
        self.api_path = NETWORK_GROUPS_ENDPOINT.format(self.domain_uuid)
        self.debug_print("api_path: {0}".format(self.api_path))

        ret_val, response = self._api_run("get", self.api_path, self)
        if phantom.is_fail(ret_val):
            return self.get_status()

        try:
            network_group_list = response["items"]
            for item in network_group_list:
                if item["name"] == self.network_group_object:
                    self.netgroup_uuid = item["id"]
        except Exception as e:
            message = "Received unexpected response from the server. {0}".format(str(e))
            self.debug_print(message)
            return self.set_status(phantom.APP_ERROR, message)

        return phantom.APP_SUCCESS

    def _get_group_object_networks(self, action_result):
        """ Gets network groups """
        # Get the current list of static routes from the Target Host
        self.api_path = HOST_NETWORK_GROUPS_ENDPOINT.format(self.domain_uuid, self.netgroup_uuid)
        self.debug_print("api_path: {0}".format(self.api_path))

        ret_val, response = self._api_run("get", self.api_path, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self.network_group_list = response.get("literals")
        return phantom.APP_SUCCESS

    def _get_firepower_deployable_devices(self, action_result):
        """ Gets deployable devices """
        # Get the current list of devices in the domain
        self.api_path = DEPLOYABLE_DEVICES_ENDPOINT.format(self.domain_uuid)
        self.debug_print("api_path: {0}".format(self.api_path))

        ret_val, response = self._api_run("get", self.api_path, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            items = response.get("items")
            if not items:
                self.nothing_to_deploy = True
                return phantom.APP_SUCCESS
            for item in items:
                self.firepower_deployable_devices.append(
                    {"name": item["device"]["name"],
                     "id": item["device"]["id"]})
        except Exception as e:
            message = "An error occurred while processing deployable devices"
            self.debug_print("{}. {}".format(message, str(e)))
            return action_result.set_status(phantom.APP_ERROR, message)

        return phantom.APP_SUCCESS

    def _get_headers(self, headers):
        self.token = headers.get("X-auth-access-token")
        self.domain_uuid = headers.get("DOMAIN_UUID")
        self.headers.update({"X-auth-access-token": self.token})

    def _get_token(self, action_result, force=False):
        """ Gets token """
        token = self._state.get("X-auth-access-token")
        domain_id = self._state.get("DOMAIN_UUID")

        if not force and token and domain_id:
            self._get_headers(self._state)
        else:
            ret_val, headers = self._api_run("post", TOKEN_ENDPOINT, action_result, headers_only=True, first_try=False)
            if phantom.is_fail(ret_val):
                self._state.pop("X-auth-access-token", None)
                self._state.pop("DOMAIN_UUID", None)
                return action_result.get_status()

            self._get_headers(headers)
            self._state["X-auth-access-token"] = self.token
            self._state["DOMAIN_UUID"] = self.domain_uuid

        return phantom.APP_SUCCESS

    def _api_run(self, method, resource, action_result, json_body=None, headers_only=False, first_try=True):
        """ Makes a REST call to the API """
        request_method = getattr(requests, method)
        url = "https://{0}{1}".format(self.firepower_host, resource)
        if json_body:
            self.headers.update({"Content-type": "application/json"})

        result = request_method(
            url,
            auth=requests.auth.HTTPBasicAuth(
                self.username,
                self.password),
            headers=self.headers,
            json=json_body,
            verify=self.verify,
            timeout=DEFAULT_REQUEST_TIMEOUT
        )

        if not (200 <= result.status_code < 399):
            if result.status_code == 401 and first_try:
                ret_val = self._get_token(action_result, True)
                if phantom.is_fail(ret_val):
                    return self.get_status(), None

                return self._api_run(method, resource, action_result, json_body, headers_only, first_try=False)

            self.save_progress("Received status code: {}".format(result.status_code))
            message = "Error from server. Status Code: {0} Data from server: {1}".format(
                result.status_code, result.text.replace("{", "{{").replace("}", "}}")
            )

            return action_result.set_status(phantom.APP_ERROR, message), None

        if headers_only:
            return phantom.APP_SUCCESS, result.headers

        try:
            resp_json = result.json()
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. {0}".format(str(e))), None

        return phantom.APP_SUCCESS, resp_json

    def _validate_ip(self):
        """ Validates the IP """
        ip_net = ""
        try:
            ip_net = IPNetwork(self.destination_network)
        except:
            return False
        if ip_net.prefixlen in range(32) and (ip_net.network != ip_net.ip):
            self.destination_network = "{0}/{1}".format(ip_net.network, ip_net.prefixlen)
        return True

    def _gen_network_dict(self):
        """ Generates network dictionary """
        ip_and_mask = self.destination_network.split("/")
        if len(ip_and_mask) == 1 or int(ip_and_mask[1]) == 32:
            self.debug_print("IP is type Host")
            self.destination_dict = {"type": "Host",
                                     "value": "{0}".format(self.destination_network)}
        elif len(ip_and_mask) == 2 and int(ip_and_mask[1]) in range(32):
            self.debug_print("IP is type Network")
            self.destination_dict = {"type": "Network",
                                     "value": "{0}".format(self.destination_network)}
        self.debug_print("Network Dictionary: " "{0}".format(self.destination_dict))
        if self.destination_network:
            return True
        else:
            return False

    def _deploy_config(self, action_result):
        """ Deploys configuration """
        ret_val = self._get_firepower_deployable_devices(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if self.nothing_to_deploy:
            self.debug_print("Nothing to deploy")
            return phantom.APP_SUCCESS

        deployable_device_UUIDs = [device["id"] for device in self.firepower_deployable_devices]

        self.api_path = DEPLOYMENT_REQUESTS_ENDPOINT.format(self.domain_uuid)
        self.debug_print("api_path: {0}".format(self.api_path))

        body = {
            "type": "DeploymentRequest",
            "version": "0",
            "forceDeploy": True,
            "ignoreWarning": True,
            "deviceList": (deployable_device_UUIDs),
        }

        ret_val, response = self._api_run("post", self.api_path, action_result, body)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self.network_group_list = response.get("literals")
        return phantom.APP_SUCCESS

    def _handle_test_connectivity(self, param):
        """
        Called when the user presses the test connectivity
        button on the Phantom UI.
        """
        # Add an action result to the App Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        self.save_progress("Testing connectivity")

        if self.token:
            self.save_progress("Connectivity test passed")
            return action_result.set_status(phantom.APP_SUCCESS)

        self.save_progress("Connectivity test failed")
        return action_result.set_status(phantom.APP_ERROR)

    def _handle_list_networks(self, param):
        """ Lists currently blocked networks """
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result to the App Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        # Initializes the current networks and sets the URL
        ret_val = self._get_group_object_networks(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Even if the query was successfull data might not be available
        if not self.network_group_list:
            return action_result.set_status(phantom.APP_ERROR, "API Request returned no data")

        for net in self.network_group_list:
            action_result.add_data({"network": net["value"]})
        summary = {"total_routes": len(self.network_group_list)}
        action_result.update_summary(summary)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_block_ip(self, param):
        """ Blocks an IP network """
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result to the App Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        # Initializes the current networks and sets the URL
        ret_val = self._get_group_object_networks(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self.destination_network = param["ip"]

        if self._validate_ip():
            self._gen_network_dict()
        else:
            return action_result.set_status(phantom.APP_ERROR, "Invalid IP: {0}".format(self.destination_network))

        self.network_group_list.append(self.destination_dict)

        body = {
            "id": self.netgroup_uuid,
            "name": self.network_group_object,
            "literals": (self.network_group_list)
        }

        ret_val, _ = self._api_run("put", self.api_path, action_result, body)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val = self._deploy_config(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully added {0}".format(self.destination_network))

    def _handle_unblock_ip(self, param):
        """Unblocks an IP network"""
        # Add an action result to the App Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        # Initializes the current networks and sets the URL
        ret_val = self._get_group_object_networks(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self.destination_network = param["ip"]

        if self._validate_ip():
            self._gen_network_dict()
        else:
            return action_result.set_status(phantom.APP_ERROR, "Invalid IP: {0}".format(self.destination_network))

        if self.destination_dict not in self.network_group_list:
            return action_result.set_status(phantom.APP_SUCCESS, "{0} is not present in the blocklist".format(self.destination_network))

        self.network_group_list.remove(self.destination_dict)

        body = {
            "id": self.netgroup_uuid,
            "name": self.network_group_object,
            "literals": (self.network_group_list)
        }

        ret_val, _ = self._api_run("put", self.api_path, action_result, body)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val = self._deploy_config(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully deleted {0}".format(self.destination_network))

    def handle_action(self, param):
        """
        This function implements the main functionality of the AppConnector.
        It gets called for every param dictionary element in the parameters
        array. In it's simplest form it gets the current action identifier
        and then calls a member function of it's own to handle the action.
        This function is expected to create the results of the action run
        that get added to the connector run. The return value of this function
        is mostly ignored by the BaseConnector. Instead it will just loop
        over the next param element in the parameters array and call
        handle_action again.

        We create a case structure in Python to allow for any number of
        actions to be easily added.
        """
        # action_id determines what function to execute
        action_id = self.get_action_identifier()
        self.debug_print("action_id: {}".format(action_id))

        supported_actions = {
            "test connectivity": self._handle_test_connectivity,
            "list_networks": self._handle_list_networks,
            "block_ip": self._handle_block_ip,
            "unblock_ip": self._handle_unblock_ip
        }

        run_action = supported_actions[action_id]

        return run_action(param)


if __name__ == "__main__":

    import sys

    if len(sys.argv) < 2:
        print("No test json specified as input")
        sys.exit(0)

    # input a json file that contains data like the configuration and action parameters
    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = FP_Connector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
