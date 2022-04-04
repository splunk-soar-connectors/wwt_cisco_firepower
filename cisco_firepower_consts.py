HOST_NETWORK_GROUPS_ENDPOINT = "/api/fmc_config/v1/domain/{0}/object/networkgroups/{1}"
DEPLOYMENT_REQUESTS_ENDPOINT = "/api/fmc_config/v1/domain/" "{0}/deployment/deploymentrequests"
DEPLOYABLE_DEVICES_ENDPOINT = "/api/fmc_config/v1/domain/{0}/deployment/deployabledevices?limit=100&expanded=true"
NETWORK_GROUPS_ENDPOINT = "/api/fmc_config/v1/domain/{0}/object/networkgroups"
TOKEN_ENDPOINT = "/api/fmc_platform/v1/auth/generatetoken"
HEADERS = {"Accept": "application/json"}
STATE_FILE_CORRUPT_ERR = "Error occurred while loading the state file due to its unexpected format. " \
    "Resetting the state file with the default format. Please try again."
