""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from polyswarm_api.api import PolyswarmAPI
from polyswarm_api import resources, core, exceptions, settings
from connectors.core.connector import get_logger, ConnectorError
from os.path import join
from connectors.cyops_utilities.builtins import upload_file_to_cyops, download_file_from_cyops
from integrations.crudhub import make_request
import time

logger = get_logger('polyswarm')


def api_client_creation(api_key, verify_ssl):
    try:
        api = PolyswarmAPI(key=api_key, verify=verify_ssl)
        return api
    except Exception:
        raise ConnectorError('Unauthorized: Invalid API Key')


def artifact_reputation(config, params):
    api = api_client_creation(config.get('api_key'), config.get("verify_ssl"))
    try:
        instance = api.submit(params.get('artifact'), artifact_type='url')
        scan_result = wait_for_result(api, instance)
        if scan_result['result']['failed']:
            raise ConnectorError("Failed to get results the status is {0} reason being {1}".format(scan_result['status'], scan_result['reason']))
        return scan_result['result']
    except Exception as e:
        raise ConnectorError(e)


def handle_params(params):
    value = str(params.get('value'))
    input_type = params.get('input')
    try:
        if isinstance(value, bytes):
            value = value.decode('utf-8')
        if input_type == 'Attachment ID':
            if not value.startswith('/api/3/attachments/'):
                value = '/api/3/attachments/{0}'.format(value)
            attachment_data = make_request(value, 'GET')
            file_iri = attachment_data['file']['@id']
            file_name = attachment_data['file']['filename']
            logger.info('file id = {0}, file_name = {1}'.format(file_iri, file_name))
            return file_iri
        elif input_type == 'File IRI':
            if value.startswith('/api/3/files/'):
                return value
            else:
                raise ConnectorError('Invalid File IRI {0}'.format(value))
    except Exception as err:
        logger.info('handle_params(): Exception occurred {0}'.format(err))
        raise ConnectorError('Requested resource could not be found with input type "{0}" and value "{1}"'.format
                             (input_type, value.replace('/api/3/attachments/', '')))


def submitFile(file_iri):
    try:
        file_path = join('/tmp', download_file_from_cyops(file_iri)['cyops_file_path'])
        logger.info(file_path)
        return file_path
        with open(file_path, 'rb') as attachment:
            file_data = attachment.read()
        if file_data:
            files = {'file': file_data}
            return files
        raise ConnectorError('File size too large, submit file up to 32 MB')
    except Exception as Err:
        logger.error('Error in submitFile(): %s' % Err)
        raise ConnectorError('Error in submitFile(): %s' % Err)


def file_scan(config, params):
    try:
        api = api_client_creation(config.get('api_key'), config.get("verify_ssl"))
        file_iri = handle_params(params)
        files = submitFile(file_iri)
        logger.error("file path is {}".format(files))
        instance = api.submit(files)
        scan_result = wait_for_result(api, instance)
        if scan_result['result']['failed']:
            raise ConnectorError("Failed to get results the status is {0} reason being {1}".format(scan_result['status'], scan_result['reason']))
        return scan_result['result']
    except Exception as e:
        raise ConnectorError(e)


def wait_for_result(api, instance):
    start = time.time()
    timeout = settings.DEFAULT_SCAN_TIMEOUT
    while True:
        scan_result = core.PolyswarmRequest(
            api,
            {
                'method': 'GET',
                'url': '{0}/consumer/submission/{1}/{2}'.format(api.uri, api.community, int(instance.artifact_id)),
            },
            result_parser=None, ).execute()

        scan_result = scan_result.raw_result.json()

        if scan_result['result']['failed'] or scan_result['result']['window_closed']:
            return scan_result
        elif -1 < timeout < time.time() - start:
            raise exceptions.TimeoutException('Timed out waiting for scan {} to finish. Please try again.')
        else:
            time.sleep(settings.POLL_FREQUENCY)


def file_rescan(config, params):
    try:
        api = api_client_creation(config.get('api_key'), config.get("verify_ssl"))
        instance = api.rescan(params.get('hash'))
        scan_result = wait_for_result(api, instance)
        if scan_result['result']['failed']:
            raise ConnectorError("Failed to get results the status is {0} reason being {1}".format(scan_result['status'], scan_result['reason']))
        return scan_result['result']
    except Exception as e:
        raise ConnectorError(e)


def file_reputation(config, params):
    try:
        api = api_client_creation(config.get('api_key'), config.get("verify_ssl"))
        hash_ = resources.Hash.from_hashable(params.get('hash'), hash_type=None)
        results = core.PolyswarmRequest(
            api,
            {
                'method': 'GET',
                'url': '{}/search/hash/{}'.format(api.uri, hash_.hash_type),
                'params': {
                    'hash': params.get('hash'),
                },
            },
            result_parser=None,
        ).execute()
        response = results.raw_result.json()
        for result in response.get('result'):
            if result.get('failed'):
                raise ConnectorError("Failed to get result, status code is {0} and the reason being {1}".format(results.status_code, results.errors))
            if not result.get('assertions'):
                raise ConnectorError('Artifact not scanned yet - Run rescan for this hash')
            return result

    except Exception as e:
        raise ConnectorError(e)


def _check_health(config: dict) -> bool:
    try:
        api = api_client_creation(config.get('api_key'), config.get("verify_ssl"))
        api.submit('https://polyswarm.io', artifact_type='url')
        return True
    except Exception as e:
        raise ConnectorError("Invalid API Key")


operations = {
    'get_url_reputation': artifact_reputation,
    'get_ip_reputation': artifact_reputation,
    'get_domain_reputation': artifact_reputation,
    'get_file_reputation': file_reputation,
    'file_scan': file_scan,
    'file_rescan': file_rescan
}
