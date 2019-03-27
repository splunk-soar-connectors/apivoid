# File: apivoid_consts.py
# Copyright (c) 2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL – Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

APIVOID_ACTUAL_URL = '{base_url}/{endpoint}/pay-as-you-go'
APIVOID_TEST_CONNECTIVITY_ENDPOINT = 'sslinfo/v1'
APIVOID_SSL_INFO_ENDPOINT = 'sslinfo/v1'
APIVOID_IP_REPUTATION_ENDPOINT = 'iprep/v1'
APIVOID_DOMAIN_REPUTATION_ENDPOINT = 'domainbl/v1'
APIVOID_CONFIG_SERVER_URL = 'server_url'
APIVOID_CONFIG_APIKEY = 'api_key'
APIVOID_CONST_STATS = 'stats'
APIVOID_CONST_HOST = 'host'
APIVOID_CONST_IP = 'ip'
APIVOID_CONST_DOMAIN = 'domain'
APIVOID_INVALID_IP_MESSAGE = 'Invalid IP provided: {ip}'
APIVOID_GET_CERT_INFO_SUCCESS_MSG = 'Received Certificate information for domain {domain}'
APIVOID_NO_ENGINES_FOUND_MSG = 'No engines found in blacklist category'
APIVOID_CONNECTIVITY_MSG = 'Connecting to server'
APIVOID_TEST_CONNECTIVITY_PASS_MSG = 'Test Connectivity Passed'
APIVOID_TEST_CONNECTIVITY_FAIL_MSG = 'Test Connectivity Failed'
