""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from polyswarm_api.api import PolyswarmAPI
from connectors.core.connector import get_logger, ConnectorError
from os.path import join
from connectors.cyops_utilities.builtins import upload_file_to_cyops, download_file_from_cyops
from integrations.crudhub import make_request

logger = get_logger('polyswarm')


def api_client_creation(api_key, verify_ssl):
    try:
        api = PolyswarmAPI(key=api_key, verify=verify_ssl)
        return api
    except Exception:
        raise ConnectorError('Unauthorized: Invalid API Key')


def artifact_reputation(config, params):
    api = api_client_creation(config.get('api_key'), config.get("verify_ssl"))
    positives = 0
    total = 0
    try:
        instance = api.submit(params.get('artifact'), artifact_type='url')
        result = api.wait_for(instance)
        if result.failed:
            raise ConnectorError("Invalid URL")
        for assertion in result.assertions:
            if assertion.verdict:
                positives += 1
            total += 1
        return {
            "positives": positives,
            "total": total,
            "permalink": result.permalink
        }
        return result
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


def evaluate_assertions(result):
    positives = 0
    total = 0
    for assertion in result.assertions:
        if assertion.verdict:
            positives += 1
        total += 1

    return {
        'Positives': positives,
        'Total': total,
        'PolyScore': result.polyscore,
        'sha256': result.sha256,
        'sha1': result.sha1,
        'md5': result.md5,
        'Extended type': result.extended_type,
        'First Seen': result.first_seen,
        'Last Seen': result.last_seen,
        'Permalink': result.permalink
    }


def file_scan(config, params):
    try:
        api = api_client_creation(config.get('api_key'), config.get("verify_ssl"))
        file_iri = handle_params(params)
        files = submitFile(file_iri)
        logger.error("file path is {}".format(files))
        instance = api.submit(files)
        result = api.wait_for(instance)
        if result.failed:
            raise ConnectorError("Failed to get results")
        return evaluate_assertions(result)
    except Exception as e:
        raise ConnectorError(e)


def file_rescan(config, params):
    try:
        api = api_client_creation(config.get('api_key'), config.get("verify_ssl"))
        instance = api.rescan(params.get('hash'))
        result = api.wait_for(instance)
        if result.failed:
            raise ConnectorError("Failed to get results")
        return evaluate_assertions(result)
    except Exception as e:
        raise ConnectorError(e)


def file_reputation(config, params):
    try:
        api = api_client_creation(config.get('api_key'), config.get("verify_ssl"))
        results = api.search(params.get('hash'))
        for result in results:
            if result.failed:
                raise ConnectorError("Failed to get result.")
            if not result.assertions:
                raise ConnectorError('Artifact not scanned yet - Run rescan for this hash')
            return evaluate_assertions(result)
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
    'url_reputation': artifact_reputation,
    'ip_reputation': artifact_reputation,
    'domain_reputation': artifact_reputation,
    'file_reputation': file_reputation,
    'file_scan': file_scan,
    'file_rescan': file_rescan
}
