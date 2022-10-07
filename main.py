from asyncio.log import logger
from collections import UserDict
from ibm_schematics.schematics_v1 import SchematicsV1
from ibm_cloud_sdk_core.authenticators import IAMAuthenticator, BearerTokenAuthenticator
import os
import logging
import requests
import json
import time

def get_logger():
    logging.basicConfig(level=logging.DEBUG)
    return logging.getLogger(__name__)
    
def get_schematics_instance():
    logger = get_logger()
    apikey = os.environ.get('IBM_SCHEMATICS_APIKEY', None)
    url = os.environ.get('IBM_SCHEMATICS_URL', None)

    if apikey == None or url == None:
        logger.error("Failed to fetch API or URL")
        return None
    authenticator = IAMAuthenticator(apikey=apikey, client_id='bx', client_secret='bx', url='https://iam.cloud.ibm.com/identity/token')
    service = SchematicsV1(authenticator=authenticator)
    service.set_service_url(url)
    return service

def get_refresh_token(apikey):
     authenticator = IAMAuthenticator(apikey=apikey, client_id='bx', client_secret='bx', url='https://iam.cloud.ibm.com/identity/token')
     tm = authenticator.token_manager
     tm.get_token()
     return tm.refresh_token

def get_access_token(apikey):
     authenticator = IAMAuthenticator(apikey=apikey, client_id='bx', client_secret='bx', url='https://iam.cloud.ibm.com/identity/token')
     tm = authenticator.token_manager
     tm.get_token()
     return tm.access_token

def generate_token(apikey, iam_url, is_refresh_token):
    data = {'grant_type': 'urn:ibm:params:oauth:grant-type:apikey', 'apikey': apikey }
    print(data)
    response = requests.post('https://iam.cloud.ibm.com/identity/token', data=data, headers={'Content-Type': 'application/x-www-form-urlencoded'})
    if response.status_code == requests.codes['ok']:
        if is_refresh_token:
            return response.json()['refresh_token']
        else:
            return response.json()['access_token']
    else:
        return ""

def main():
    # 1. Initialise config
    # Workspace-id, Auth-token/api-key, schematics-endpoint

    logger = get_logger()
    workspace_id = os.environ.get('WORKSPACE_ID', None)
    if workspace_id == None:
        logger.error("workspace id is not provided to detect drift")
        return False
    # 2. Run task - 1: Detect drift
    apikey = os.environ.get('IBM_SCHEMATICS_APIKEY', None)
    iam_url = os.environ.get('IBM_IAM_URL', None)
    
    service = get_schematics_instance()
    terraform_command_model = {
        'command': 'drift',
        'command_name': 'drift',
        'command_desc': 'command to detect configuration drift',
    }

    generated_token = get_refresh_token(apikey)
    logger.info("generated_token: %s", generated_token)
    workspace_activity_command_result = service.run_workspace_commands(
        w_id=workspace_id,
        refresh_token=generated_token,
        commands=[terraform_command_model],
        operation_name='drift detection',
        description='drift detection'
    ).get_result()

    logger.info(json.dumps(workspace_activity_command_result, indent=2))

    # activityid = json.loads(workspace_activity_command_result)["activityid"]
    activityid = workspace_activity_command_result['activityid']
    logger.info("Activity id: %s", activityid)

    # 3. Poll for the drift activity
    template_id = None
    logs_url = None
    for i in range(1, 10):
        time.sleep(10)
        out = service.get_workspace_activity(workspace_id, activityid).get_result()
        logger.info("activity status:  %s", out['status'])
        if out['status'] == "COMPLETED" :
            template_id = out['templates'][0]['template_id']
            logs_url = out['templates'][0]['log_url']
            break

    # 4. Run task - 2: Get logs
    content = None
    if logs_url is not None:
        logger.info("logs url: %s", logs_url)
        response = requests.get(url=logs_url, headers={"Authorization": get_access_token(apikey)})
        content = response.content

    # 5. Run task - 3: Analyse logs
    if content is not None:
        if "configuration drift identfied" in str(content):
            logger.info("drift detected")

    # 6. Run task - 4: Send notification

if __name__ == "__main__":
    main()
