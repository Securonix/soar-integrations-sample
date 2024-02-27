
from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging
import requests

class MyFirstIntegration():

    def __init__(self) -> None:
        self.logger = logging.getLogger()
        pass

    def addtowatchlist(self, request: RequestBody) -> ResponseBody:
        username = request.connectionParameters['username']
        password = request.connectionParameters['password']
        serverurl = request.connectionParameters['serverurl']
        domain = request.connectionParameters['domain']
        addwatchlistname = request.parameters['addwatchlistname']
        containerdata = request.parameters['containerdata']
  # Step 1: Extract parameters from containerdata
        if containerdata:
            tenant_name = containerdata.get('tenantname')
            entity_type = containerdata.get('entityType')
            resource_group_id = containerdata.get('resourcegroupid')
            entity_id = containerdata.get('entityId')

            if all([tenant_name, entity_type, resource_group_id, entity_id]):
                # Step 2: Get Token
                token_url = f'{serverurl}/ws/token/generate'
                auth = (username, password)

                try:
                    # Make a POST request to generate the token
                    token_response = requests.post(token_url, auth=auth)
                    token_response.raise_for_status()  # Check for HTTP errors

                    # Extract the token from the response
                    token = token_response.json().get('token')

                    # Step 3: Add to Watchlist
                    add_to_watchlist_url = f'{serverurl}/ws/incident/addToWatchlist'
                    watchlist_params = {
                        'tenantname': tenant_name,
                        'entityType': entity_type,
                        'watchlistname': addwatchlistname,
                        'expirydays': 10,
                        'resourcegroupid': resource_group_id,
                        'entityId': entity_id
                    }

                    # Make a POST request to add to the watchlist
                    watchlist_response = requests.post(add_to_watchlist_url, headers={'token': token}, params=watchlist_params)
                    watchlist_response.raise_for_status()  # Check for HTTP errors

                    # Return the full response content
                    return watchlist_response.json()
                except requests.exceptions.RequestException as e:
                    return {'Status': 'Error', 'Message': f'Failed to complete the operation: {str(e)}'}
            else:
                return {'Status': 'Error', 'Message': 'Required parameters are missing in containerdata'}
        else:
            return {'Status': 'Error', 'Message': 'Containerdata is missing'}

    def createwatchlist(self, request: RequestBody) -> ResponseBody:
        username = request.connectionParameters['username']
        password = request.connectionParameters['password']
        serverurl = request.connectionParameters['serverurl']
        domain = request.connectionParameters['domain']
        createwatchlistname = request.parameters['createwatchlistname']
        # Step 1: Generate Token
        token_url = f'{serverurl}/ws/token/generate'
        auth = (username, password)

        try:
            # Make a POST request to generate the token
            token_response = requests.post(token_url, auth=auth)
            token_response.raise_for_status()  # Check for HTTP errors

            # Extract the token from the response
            token = token_response.json().get('token')

            # Step 2: Create Watchlist
            if createwatchlistname:
                create_watchlist_url = f'{serverurl}/ws/incident/createWatchlist'
                watchlist_params = {
                    'watchlistname': createwatchlistname,
                    'tenantname': '64april_r2_mssp',  # You may need to adjust this value
                    'token': token
                }

                # Make a POST request to create the watchlist
                watchlist_response = requests.post(create_watchlist_url, params=watchlist_params)
                watchlist_response.raise_for_status()  # Check for HTTP errors

                # Handle the watchlist creation response as needed
                watchlist_status = watchlist_response.json().get('Status')

                return {'Status': watchlist_response.json()}
            else:
                return {'Status': 'Error', 'Message': 'Watchlist name is missing'}

        except requests.exceptions.RequestException as e:
            return {'Status': 'Error', 'Message': f'Failed to complete the operation: {str(e)}'}


    def test_connection(self, connectionParameters: dict):
        username = connectionParameters['username']
        password = connectionParameters['password']
        serverurl = connectionParameters['serverurl']
        domain = connectionParameters['domain']
        try:
            response = requests.get(serverurl, auth=(username, password))
            response.raise_for_status() 

            if response.status_code == 200:
              return 'Connection Successful'
            else:
                raise Exception(f"Connection failed with status code {response.status_code}")
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to establish connection: {str(e)}")
