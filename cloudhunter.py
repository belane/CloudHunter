#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# CloudHunter
# Version: 0.4

import sys
import socket
import requests
import argparse
import json
try:
    import boto3
except ImportError:
    print('Install boto3 for full AWS support.')
from queue import Queue
from threading import Thread
from enum import Enum


googleCloud = {
    'Google Storage': 'storage.googleapis.com',
    'Google App Engine': 'appspot.com'
}

awsCloud = {
    'AWS Bucket': 's3.amazonaws.com'
}

azureCloud = {
    'Storage Files': 'file.core.windows.net',
    'Storage Blobs': 'blob.core.windows.net',
    'Storage Queues': 'queue.core.windows.net',
    'Storage Tables': 'table.core.windows.net',
    'App Management': 'scm.azurewebsites.net',
    'App Azure': 'azurewebsites.net',
    'App Web': 'p.azurewebsites.net',
    'CloudApp': 'cloudapp.net',
    'Key Vaults': 'vault.azure.net',
    'Azure CDN': 'azureedge.net',
    'Search Appliance': 'search.windows.net',
    'API Services': 'azure-api.net',
    'Hosted Domain': 'onmicrosoft.com',
    'Databases-Redis': 'redis.cache.windows.net',
    'Databases-CosmosDB': 'documents.azure.com',
    'Databases-MSSQL': 'database.windows.net',
    'Email': 'mail.protection.outlook.com',
    'SharePoint': 'sharepoint.com'
}


class State(Enum):
    CLOSE = 'CLOSE'
    DOMAIN = 'DOMAIN'
    PRIVATE = 'PRIVATE'
    OPEN = 'OPEN'
    UNKNOWN = 'UNKNOWN'


class Risk(Enum):
    LOW = 0
    MEDIUM = 34
    HIGH = 31


class Bucket(object):
    def __init__(self, name, domain, cloud='Generic', srv_name='Generic'):
        self.name = name
        self.domain = domain
        self.cloud = cloud
        self.srv_name = srv_name
        self.state = State.CLOSE
        self.risk = Risk.LOW
        self.details = []

    def process_status(self, response):
        if(response == False):
            self.state = State.DOMAIN
            return
        elif response.status_code == 200:
            self.state = State.OPEN
            self.risk = Risk.MEDIUM
        elif response.status_code in [400, 401, 403]:
            self.state = State.PRIVATE
        elif response.status_code in [500, 502, 503]:
            self.state = State.OPEN
            self.risk = Risk.MEDIUM
            self.details.append('WebApp Error')
        else:
            self.state = State.UNKNOWN
            self.risk = Risk.MEDIUM
            self.details.append('Response: {}'.format(response.status_code))

        if self.name == base_name:
            self.risk = Risk.MEDIUM

        if(len(response.history) != 0 and response.history[0].status_code in [301, 302]):
            self.details.append('Redirect ' + response.url)

        self.process_rights()

    def echo(self):
        print('\033[0;{}m{}{:<22}{:<42}\t{:<10}{}\033[0;0m'.format(
            self.risk.value, ' ' * 4, self.srv_name, self.domain, self.state.value, ' | '.join(self.details)))

        if verbose and hasattr(self, 'acl'):
            print(json.dumps(self.acl, indent=4))

    def process_rights(self):
        if self.state != State.OPEN:
            return
        if self.cloud == 'google':
            self._google_acl()
        elif self.cloud == 'aws':
            self._aws_acl()
        elif self.cloud == 'azure':
            self._azure_acl()

    def _azure_acl(self):
        #azure_api = 'https://{}.blob.core.windows.net/{}?restype=container&comp=acl'.format(self.name,self.name)
        #remote_acl = requests.get(azure_api)
        # print(remote_acl)
        pass

    def _google_acl(self):
        google_api = 'https://www.googleapis.com/storage/v1/b/{}/iam/testPermissions?permissions=storage.buckets.delete&permissions=storage.buckets.get&permissions=storage.buckets.getIamPolicy&permissions=storage.buckets.setIamPolicy&permissions=storage.buckets.update&permissions=storage.objects.create&permissions=storage.objects.delete&permissions=storage.objects.get&permissions=storage.objects.list&permissions=storage.objects.update'.format(
            self.name)
        remote_acl = requests.get(google_api).json()

        if remote_acl.get('permissions'):
            self.acl = remote_acl['permissions']
            user = 'AllUsers'
            symb = ''

            if 'storage.objects.list' in self.acl:
                symb += 'L'
            if 'storage.objects.get' in self.acl:
                symb += 'R'
            if 'storage.objects.create' in self.acl or \
                'storage.objects.delete' in self.acl or \
                    'storage.objects.update' in self.acl:
                self.risk = Risk.HIGH
                symb += 'W'
            if 'storage.buckets.setIamPolicy' in self.acl:
                self.risk = Risk.HIGH
                symb += 'V'

            self.details.append('{} [{}]'.format(user, symb))

    def _aws_acl(self):
        try:
            s3 = boto3.client('s3')
            remote_acl = s3.get_bucket_acl(Bucket=self.name)
            if 'Grants' in remote_acl:
                self.acl = remote_acl['Grants']
                rights = {}

                for right in self.acl:
                    if right['Grantee']['Type'] == 'CanonicalUser' and 'DisplayName' in right['Grantee']:
                        user = right['Grantee']['DisplayName']
                    elif right['Grantee']['Type'] == 'Group':
                        user = right['Grantee']['URI'].split('/')[-1]
                    else:
                        user = right['Grantee']['ID'][:8]

                    if right['Permission'] == 'READ' or right['Permission'] == 'READ_ACP':
                        symb = 'R'
                    elif right['Permission'] == 'WRITE' or right['Permission'] == 'WRITE_ACL':
                        self.risk = Risk.HIGH
                        symb = 'W'
                    elif right['Permission'] == 'FULL_CONTROL':
                        self.risk = Risk.HIGH
                        symb = 'F'

                    if user not in rights:
                        rights[user] = symb
                    elif symb not in rights[user]:
                        rights[user] += symb

                for user, symb in rights.items():
                    self.details.append('{} [{}]'.format(user, symb))

        except:
            pass


def check_dns(hostname):
    try:
        ip = socket.gethostbyname(hostname)
        if ip in ['0.0.0.0', '127.0.0.1']:
            return False
        return True
    except socket.error:
        return False


def check_host(host):
    try:
        response = requests.get('http://' + host)
    except:
        return False
    if response.status_code in [404]:
        return False
    return response


def generate_permutations(base_name, dict_file):
    p = []
    p.append(base_name)
    rules = ['{}-{}', '{}.{}', '{}{}']

    with open(dict_file, 'r') as f:
        lines = f.read().splitlines()
        for affix in lines:
            p += [x.format(affix, base_name) for x in rules]
            p += [x.format(base_name, affix) for x in rules]

    return p


def check_cloud(cloud_dict, names, cloud='default'):
    q = Queue(maxsize=0)
    results = []

    for srv_name, srv_url in cloud_dict.items():
        for name in names:
            domain = '{}.{}'.format(name, srv_url)
            q.put((srv_name, domain, name))

    for w in range(num_threads):
        worker = Thread(target=check_cloud_worker, args=(q, results, cloud))
        worker.setDaemon(True)
        worker.start()

    q.join()
    return results


def check_cloud_worker(q, results, cloud):
    while not q.empty():
        work = q.get()
        srv_name = work[0]
        domain = work[1]
        name = work[2]

        if(verbose):
            print('[d]   checking {}'.format(domain))

        if check_dns(domain):
            response = check_host(domain)
            if(response != False or cloud == 'azure'):
                b = Bucket(name, domain, cloud, srv_name)
                b.process_status(response)

                results.append(b)
                if not show_open_only or b.state == State.OPEN:
                    b.echo()

        q.task_done()

    return True


def show_banner():
    banner = '''\033[0;32m
           ________                ____  __            __
          / ____/ /___  __  ______/ / / / /_  ______  / /____  _____
         / /   / / __ \/ / / / __  / /_/ / / / / __ \/ __/ _ \/ ___/
        / /___/ / /_/ / /_/ / /_/ / __  / /_/ / / / / /_/  __/ /
        \____/_/\____/\__,_/\__,_/_/ /_/\__,_/_/ /_/\__/\___/_/
        \n\033[0;0m'''
    print(banner)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='CloudHunter. Searches for AWS, Azure and Google cloud storage buckets.')
    parser.add_argument('base_name', metavar='basename', type=str,
                        nargs='+', help='Company name or any base name.')
    parser.add_argument('-p', '--permutations-file', metavar='file',
                        type=str, default='permutations.txt', help='Permutations file.')
    parser.add_argument('-t', '--threads', metavar='num',
                        type=int, default=5, help='Threads.')
    parser.add_argument('-b', '--base-only',  action='store_true',
                        help='checks only the base name, skips permutations generation.')
    parser.add_argument('-v', '--verbose',
                        action='store_true', help='verbose log')
    parser.add_argument('-o', '--open-only',
                        action='store_true', help='show only open buckets.')
    args = parser.parse_args()
    show_banner()

    num_threads = min(300, args.threads)
    show_open_only = args.open_only
    verbose = args.verbose
    results = []
    base_name = args.base_name[0].strip().lower()

    if(args.base_only):
        permutations = [base_name]
    else:
        permutations = generate_permutations(base_name, args.permutations_file)

    srv_len = len(azureCloud) + len(googleCloud) + len(awsCloud)
    print('[>] {} name permutations.'.format(len(permutations)))
    print('[>] {} tries, be patient.\n'.format(len(permutations) * srv_len))

    print('\n[+] Check Google Cloud')
    results += check_cloud(googleCloud, permutations, 'google')

    print('\n[+] Check Amazon Cloud')
    results += check_cloud(awsCloud, permutations, 'aws')

    print('\n[+] Check Azure Cloud')
    results += check_cloud(azureCloud, permutations, 'azure')
