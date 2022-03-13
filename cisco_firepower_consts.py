HOST_NETWORK_GROUPS_ENDPOINT = "/api/fmc_config/v1/domain/{0}/object/networkgroups/{1}"
DEPLOYMENT_REQUESTS_ENDPOINT = "/api/fmc_config/v1/domain/" "{0}/deployment/deploymentrequests"
DEPLOYABLE_DEVICES_ENDPOINT = "/api/fmc_config/v1/domain/{0}/deployment/deployabledevices?limit=100&expanded=true"
NETWORK_GROUPS_ENDPOINT = "/api/fmc_config/v1/domain/{0}/object/networkgroups"
TOKEN_ENDPOINT = "/api/fmc_platform/v1/auth/generatetoken"
HEADERS = {"Accept": "application/json"}
STATE_FILE_CORRUPT_ERR = "Error occurred while loading the state file due to its unexpected format. " \
    "Resetting the state file with the default format. Please try again."
ERR_CONNECT = "Failed to connect to the database"
ERR_NO_PARAMS_PRESENT = "None of the parameters specified, please specify one of {param_names}."
SUCC_NO_MATCH = "Query executed successfully, but signature not found"
ERR_EXECUTING_QUERY = "Error executing query"
ERR_FETCHING_RESULTS = "Error fetching results"
JSON_SNORT_ID = "snort_id"
JSON_BUGTRAQ_ID = "bugtraq_id"
JSON_SVID = "svid"
JSON_TOTAL_SIGS = "total_signatures"
JDBC_DB_URL = "jdbc:vjdbc:rmi://{device}:{port}/VJdbc,eqe"
JDBC_DRIVER_CLASS = "de.simplicit.vjdbc.VirtualDriver"
JDBC_DRIVER_JAR_FILES = [
    "commons-logging-1.2.jar",
    "vjdbc-2.0-ejb-client.jar"
]
DEFAULT_PORT = 2000
# The columns that will be queried for, keep it a list, easy to match the results to this column to create a result dictionary
SIG_INFO_COLUMNS = ["available_exploits", "bugtraq_id", "exploit", "remote", "rna_vuln_id", "short_description", "snort_id", "title"]
MSG_TIMEOUT_TRY_AGAIN = "Got timeout error, trying again"

# Constants relating to "_validate_integer"
INVALID_INTEGER_ERR_MSG = "Please provide a valid integer value in the {} parameter"
NEGATIVE_INTEGER_ERR_MSG = "Please provide a valid non-negative integer value in the {} parameter"
ZERO_INTEGER_ERR_MSG = "Please provide a valid non-zero integer value in the {} parameter"
