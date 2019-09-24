#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# CloudHunter
# Version: 0.3

import sys
import socket
import requests
import json
from queue import Queue
from threading import Thread


verbose = False
show_open_only = False

googleCloud = {
    'Google Storage':'storage.googleapis.com',
    'Google App Engine':'appspot.com'
}

awsCloud = {
    'AWS Bucket':'s3.amazonaws.com'
}

azureCloud = {
    'Microsoft Hosted Domain':'onmicrosoft.com',
    'App Services - Management':'scm.azurewebsites.net',
    'App Services - Azure':'azurewebsites.net',
    'App Services - Web':'p.azurewebsites.net',
    'App Services - CloudApp':'cloudapp.net',
    'Storage Accounts - Files':'file.core.windows.net',
    'Storage Accounts - Blobs':'blob.core.windows.net',
    'Storage Accounts - Queues':'queue.core.windows.net',
    'Storage Accounts - Tables':'table.core.windows.net',
    'Email':'mail.protection.outlook.com',
    'SharePoint':'sharepoint.com',
    'Databases-Redis':'redis.cache.windows.net',
    'Databases-Cosmos DB':'documents.azure.com',
    'Databases-MSSQL':'database.windows.net',
    'Key Vaults':'vault.azure.net',
    'Azure CDN':'azureedge.net',
    'Search Appliance':'search.windows.net',
    'API Services':'azure-api.net'
}

class Bucket(object):
    def __init__(self, url, name='Generic'):
        self.state = ''
        self.details = []
        self.url = url
        self.name = name

    def process_status(self, response):
            if(response == False): return

            if response.status_code == 200:
                self.state = 'OPEN'
            elif response.status_code in [401, 403]:
                self.state = 'PRIVATE'
            elif response.status_code in [500, 502, 503]:
                self.state = 'OPEN'
                self.details.append('Server error')
            else:
                self.state = response.status_code

            if(len(response.history) != 0 and response.history[0].status_code in [301, 302]):
                self.details.append('Redirect ' + response.url)

    def echo(self):
        print('{}{:<20}\t{:<42}\t{:<8}\t {}'.format(' ' * 4, self.name, self.url, self.state, ','.join(self.details)))


def check_dns(hostname):
    try:
        ip = socket.gethostbyname(hostname)
        if ip in ['0.0.0.0', '127.0.0.1']: return False
        return True
    except socket.error:
        return False


def check_host(host):
    try:
        response = requests.get('http://' + host)
    except:
        return False
    if response.status_code in [400, 404]: return False
    return response


def generate_permutations(name, dict_file):
    p = []
    p.append(name)
    with open(dict_file, 'r') as f:
        lines = f.read().splitlines()
        for l in lines:
            p.append('{}-{}'.format(l, name))
            p.append('{}.{}'.format(l, name))
            p.append('{}{}'.format(l, name))
            p.append('{}-{}'.format(name, l))
            p.append('{}.{}'.format(name, l))
            p.append('{}{}'.format(name, l))
    return p


def get_google_rights(name):
    desc = []
    google_api = 'https://www.googleapis.com/storage/v1/b/{}/iam/testPermissions?permissions=storage.buckets.delete&permissions=storage.buckets.get&permissions=storage.buckets.getIamPolicy&permissions=storage.buckets.setIamPolicy&permissions=storage.buckets.update&permissions=storage.objects.create&permissions=storage.objects.delete&permissions=storage.objects.get&permissions=storage.objects.list&permissions=storage.objects.update'.format(name)
    rights = requests.get(google_api).json()
 
    if rights.get('permissions'):
        if 'storage.objects.list' in rights['permissions']:
            desc.append('List')
        if 'storage.objects.get' in rights['permissions']:
            desc.append('Read')
        if 'storage.objects.create' in rights['permissions'] or \
            'storage.objects.delete' in rights['permissions'] or \
            'storage.objects.update' in rights['permissions']:
            desc.append('Write')
        if 'storage.buckets.setIamPolicy' in rights['permissions']:
            desc.append('Vulnerable!')
        return desc, rights['permissions']
    return desc, ''


def check_cloud(cloud, names, type='default'):
    q = Queue(maxsize=0)
    num_threads = 10
    results = []

    for srv, url in cloud.items():
        for p in names:
            query = '{}.{}'.format(p, url)
            q.put((srv, query, p))

    for x in range(num_threads):
        worker = Thread(target=check_cloud_worker, args=(q, results, type))
        worker.setDaemon(True)
        worker.start()

    q.join()
    return results


def check_cloud_worker(q, results, type):
    while not q.empty():
        work = q.get()
        srv = work[0]
        query = work[1]
        p = work[2]

        if(verbose):
            print('[d]   checking {}'.format(query))

        if not check_dns(query):
            q.task_done()
            continue

        response = check_host(query)
        if(response != False):
            b = Bucket(query, srv)
            b.process_status(response)
            if(b.state == 'OPEN' and type == 'google'):
                x, b.rights = get_google_rights(p)
                b.details += x
        elif(type == 'azure'):
            b = Bucket(query, srv)
            b.state = 'DOMAIN'
        else:
            q.task_done()
            continue

        if(b.state):
            results.append(b)
            if not show_open_only or b.state == 'OPEN':
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
    show_banner()

    if(len(sys.argv) < 2):
        print('Usage: {} company-name\n'.format(sys.argv[0]))
        exit(1)

    results = []   
    base_name = sys.argv[1].strip().lower()
    permutations = generate_permutations(base_name, 'permutations.txt')
    srv_len = len(azureCloud) + len(googleCloud) + len(awsCloud)

    print('[>] {} name permutations.'.format(len(permutations)))
    print('[>] {} tries, be patient.\n'.format(len(permutations) * srv_len))

    print('\n[+] Check Google Cloud')
    results += check_cloud(googleCloud, permutations, 'google')
 
    print('\n[+] Check Amazon Cloud')
    results += check_cloud(awsCloud, permutations, 'aws')

    print('\n[+] Check Azure Cloud')
    results += check_cloud(azureCloud, permutations, 'azure')
