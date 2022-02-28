CISCO_FIREPOWER_JSON_DEVICE = "firepower_host"
CISCO_FIREPOWER_JSON_PORT = "port"
CISCO_FIREPOWER_JSON_USERNAME = "username"
CISCO_FIREPOWER_JSON_PASSWORD = "password"
CISCO_FIREPOWER_JSON_SNORT_ID = "snort_id"
CISCO_FIREPOWER_JSON_BUGTRAQ_ID = "bugtraq_id"
CISCO_FIREPOWER_JSON_SVID = "svid"
CISCO_FIREPOWER_JSON_TOTAL_SIGS = "total_signatures"
CISCO_FIREPOWER_ERR_EXECUTING_QUERY = "Error executing query"
CISCO_FIREPOWER_ERR_FETCHING_RESULTS = "Error fetching results"
CISCO_FIREPOWER_JSON_TOTAL_SIGS = "total_signatures"
CISCO_FIREPOWER_SUCC_NO_MATCH = "Query executed successfully, but signature not found"
CISCO_FIREPOWER_JDBC_DB_URL = "jdbc:vjdbc:rmi://{device}:{port}/VJdbc,eqe"
CISCO_FIREPOWER_JDBC_DRIVER_CLASS = "com.sourcefire.vjdbc.VirtualDriver"
CISCO_FIREPOWER_JDBC_DRIVER_JAR_FILES = ["commons-logging-1.1.jar", "vjdbc.jar"]
CISCO_FIREPOWER_DEFAULT_PORT = 2000

CISCO_FIREPOWER_ERR_NO_PARAMS_PRESENT = "None of the parameters specified, please specify one of {param_names}."
# The columns that will be queried for, keep it a list, easy to match the results to this column to create a result dictionary
CISCO_FIREPOWER_SIG_INFO_COLUMNS = ["available_exploits", "bugtraq_id", "exploit", "remote", "rna_vuln_id", "short_description", "snort_id", "title"]

# Constants relating to error messages
CISCO_FIREPOWER_MSG_TIMEOUT_TRY_AGAIN = "Got timeout error, trying again"
CISCO_FIREPOWER_ERR_CONNECT = "Failed to connect to device"
CISCO_FIREPOWER_VALIDATE_INTEGER_MESSAGE = "Please provide a valid integer value in the {key} parameter"
CISCO_FIREPOWER_ERR_TEST_CONN_FAILED = "Test Connectivity Failed"
CISCO_FIREPOWER_SUCC_TEST_CONN_PASSED = "Test Connectivity Passed"
