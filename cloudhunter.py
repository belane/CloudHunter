#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__title__ = "CloudHunter"
__url__ = "https://github.com/belane/CloudHunter"
__version__ = "0.7.1"

import re
import json
import string
import urllib3
import requests
import argparse
import tldextract
import xmltodict
import dns.resolver
from enum import Enum
from queue import Queue
from random import choices
from itertools import cycle
from threading import Thread
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

TIMEOUT = 7
USER_AGENT = { 'User-Agent': "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36" }

googleCloud = {
    'Google Storage': 'storage.googleapis.com',
    'Google App Engine': 'appspot.com'
}

awsCloud = {
    'AWS Bucket': 's3.amazonaws.com'
}

alibabaCloud = {
    'Alibaba Bucket': 'oss-cn-hangzhou.aliyuncs.com',
    'Alibaba SH Bucket': 'oss-cn-shanghai.aliyuncs.com',
    'Alibaba NJ Bucket': 'oss-cn-nanjing.aliyuncs.com',
    'Alibaba QD Bucket': 'oss-cn-qingdao.aliyuncs.com',
    'Alibaba BJ Bucket': 'oss-cn-beijing.aliyuncs.com',
    'Alibaba ZH Bucket': 'oss-cn-zhangjiakou.aliyuncs.com',
    'Alibaba HH Bucket': 'oss-cn-huhehaote.aliyuncs.com',
    'Alibaba WU Bucket': 'oss-cn-wulanchabu.aliyuncs.com',
    'Alibaba SZ Bucket': 'oss-cn-shenzhen.aliyuncs.com',
    'Alibaba HY Bucket': 'oss-cn-heyuan.aliyuncs.com',
    'Alibaba GG Bucket': 'oss-cn-guangzhou.aliyuncs.com',
    'Alibaba CH Bucket': 'oss-cn-chengdu.aliyuncs.com',
    'Alibaba HK Bucket': 'oss-cn-hongkong.aliyuncs.com',
    'Alibaba W1 Bucket': 'oss-us-west-1.aliyuncs.com',
    'Alibaba E1 Bucket': 'oss-us-east-1.aliyuncs.com',
    'Alibaba N1 Bucket': 'oss-ap-northeast-1.aliyuncs.com',
    'Alibaba N2 Bucket': 'oss-ap-northeast-2.aliyuncs.com',
    'Alibaba S1 Bucket': 'oss-ap-southeast-1.aliyuncs.com',
    'Alibaba S2 Bucket': 'oss-ap-southeast-2.aliyuncs.com',
    'Alibaba S3 Bucket': 'oss-ap-southeast-3.aliyuncs.com',
    'Alibaba S5 Bucket': 'oss-ap-southeast-5.aliyuncs.com',
    'Alibaba S6 Bucket': 'oss-ap-southeast-6.aliyuncs.com',
    'Alibaba S7 Bucket': 'oss-ap-southeast-7.aliyuncs.com',
    'Alibaba SU Bucket': 'oss-ap-south-1.aliyuncs.com',
    'Alibaba EC Bucket': 'oss-eu-central-1.aliyuncs.com',
    'Alibaba EW Bucket': 'oss-eu-west-1.aliyuncs.com',
    'Alibaba ME Bucket': 'oss-me-east-1.aliyuncs.com'
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
    # 'Search Appliance': 'search.windows.net',
    'API Services': 'azure-api.net',
    'Hosted Domain': 'onmicrosoft.com',
    'Databases-Redis': 'redis.cache.windows.net',
    'Databases-CosmosDB': 'documents.azure.com',
    'Databases-MSSQL': 'database.windows.net',
    # 'Email': 'mail.protection.outlook.com',
    # 'SharePoint': 'sharepoint.com'
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

    def __init__(self, name, domain, cloud='generic', srv_name='Generic', enable_write = False):
        self.name = name
        self.domain = domain
        self.cloud = cloud
        self.srv_name = srv_name
        self.state = State.CLOSE
        self.risk = Risk.LOW
        self.details = []
        self.enable_write = enable_write

    def process_status(self, response):
        if(response == False):
            self.state = State.DOMAIN
            return

        if self.name == base_name:
            self.risk = Risk.MEDIUM

        if response.status_code == 200:
            self.state = State.OPEN
            self.risk = Risk.MEDIUM
            content_type = response.headers.get('Content-Type', None)
            if content_type and 'application/xml' in content_type:
                self.risk = Risk.HIGH
                self.details.append('LIST')
        elif response.status_code in [400, 401, 403]:
            self.state = State.PRIVATE
        elif response.status_code in [500, 502, 503]:
            self.state = State.OPEN
            self.risk = Risk.MEDIUM
            self.details.append('WebApp Error')
        else:
            self.state = State.UNKNOWN
            self.risk = Risk.MEDIUM
            self.details.append(f'Response: {response.status_code}')

        if(len(response.history) != 0 and response.history[0].status_code in [301, 302]):
            self.details.append(f'Redirect {response.url}')
            if 'login' in response.url or 'signin' in response.url:
                self.state = State.PRIVATE
                self.risk = Risk.LOW

        self.get_rights()

    def print_details(self):
        print('\033[0;{}m{}{:<22}{:<42}\t{:<10}{}\033[0;0m'.format(
            self.risk.value, ' ' * 4, self.srv_name, self.domain, self.state.value, ' | '.join(self.details)))

        if verbose and hasattr(self, 'acl'):
            print(json.dumps(self.acl, indent=4))

    def write_test(self):
        proof = f"proof-{''.join(choices(string.ascii_uppercase, k=4))}"
        try:
            write_test = requests.put(f'https://{self.domain}/{proof}', timeout=TIMEOUT, verify=False, headers=USER_AGENT)
        except:
            return
        if write_test.ok:
            self.state = State.OPEN
            self.risk = Risk.HIGH
            self.details.append('WRITE')
            try:
                delete_test = requests.delete(f'https://{self.domain}/{proof}', timeout=TIMEOUT, verify=False, headers=USER_AGENT)
            except:
                print(f'[d]   Error deleting proof: {self.domain} {proof}')
                return
            if not delete_test.ok:
                print(f'[d]   Error deleting proof: {self.domain} {proof}')

    def get_rights(self):
        if self.cloud == 'azure':
            self._azure_acl()
        elif self.cloud == 'alibaba':
            self._alibaba_acl()
        elif self.cloud == 'aws':
            self._aws_acl()
        elif self.cloud == 'google':
            self._google_acl()

    def _azure_acl(self):
        if 'file.core.windows.net' in self.domain:
            try:
                response = requests.get(f'https://{self.domain}/?comp=list', allow_redirects=True, timeout=15, verify=False, headers=USER_AGENT)
                if response.status_code == 200:
                    self.risk = Risk.HIGH
                    self.state = State.OPEN
                    self.details.append(f'List Shares')
                elif self.enable_write:
                    self.write_test()
            except:
                if(verbose):
                    print(f'[d]   ACL Error {self.domain}')
                return

        if 'blob.core.windows.net' in self.domain:
            COMMON_CONTAINERS = ['images', 'mycontainer', 'downloads', 'backup', 'backups', 'web', 'website', 'private', 'uploads', 'page', 'static', 'logs', 'admin']
            COMMON_CONTAINERS.append(self.name)
            if self.name != base_name:
                COMMON_CONTAINERS.append(base_name)

            findings = []
            for container in COMMON_CONTAINERS:
                try:
                    response = requests.get(f'https://{self.domain}/{container}?restype=container&comp=list', allow_redirects=True, timeout=15, verify=False, headers=USER_AGENT)
                    if response.status_code == 200:
                        findings.append(container)
                except:
                    if(verbose):
                        print(f'[d]   ACL Error {self.domain}')
                    continue
            if findings:
                self.risk = Risk.HIGH
                self.state = State.OPEN
                self.details.append(f'Containers: {",".join(findings)}')

    def _google_acl(self):
        if self.state != State.OPEN:
            return
        google_api = f'https://www.googleapis.com/storage/v1/b/{self.name}/iam/testPermissions?permissions=storage.buckets.delete&permissions=storage.buckets.get&permissions=storage.buckets.getIamPolicy&permissions=storage.buckets.setIamPolicy&permissions=storage.buckets.update&permissions=storage.objects.create&permissions=storage.objects.delete&permissions=storage.objects.get&permissions=storage.objects.list&permissions=storage.objects.update'
        try:
            remote_acl = requests.get(google_api, timeout=TIMEOUT, verify=False, headers=USER_AGENT).json()
        except:
            if self.enable_write:
                self.write_test()
            if(verbose):
                print(f'[d]   ACL Error {self.domain}')
            return

        if remote_acl.get('permissions'):
            self.acl = remote_acl['permissions']
            user = 'AllUsers'
            rights = ''

            if 'storage.objects.list' in self.acl:
                rights += 'L'
            if 'storage.objects.get' in self.acl:
                rights += 'R'
            if 'storage.objects.create' in self.acl or \
                'storage.objects.delete' in self.acl or \
                    'storage.objects.update' in self.acl:
                rights += 'W'
                self.risk = Risk.HIGH
            if 'storage.buckets.setIamPolicy' in self.acl:
                rights += 'V'
                self.risk = Risk.HIGH

            self.details.append(f'{user} [{rights}]')

    def _aws_acl(self):
        if self.state == State.OPEN:
            aws_api = f'https://{self.name}.s3.amazonaws.com/?acl'
            try:
                remote_acl = requests.get(aws_api, timeout=TIMEOUT, verify=False, headers=USER_AGENT).text
            except:
                if(verbose):
                    print(f'[d]   ACL Error {self.domain}')
                return
            acl_dict = xmltodict.parse(remote_acl, dict_constructor=dict)

            if not self._read_s3_acl(acl_dict) and self.enable_write:
                self.write_test()
        elif self.enable_write:
            self.write_test()

    def _alibaba_acl(self):
        self.srv_name = 'Alibaba Bucket'
        alibaba_api = f'https://{self.domain}/?acl'
        try:
            remote_acl = requests.get(alibaba_api, timeout=TIMEOUT, verify=False, headers=USER_AGENT).text
        except:
            if(verbose):
                print(f'[d]   ACL Error {self.domain}')
            return
        acl_dict = xmltodict.parse(remote_acl, dict_constructor=dict)

        if 'Error' in acl_dict and 'Endpoint' in acl_dict['Error']:
            self.domain = f"{self.name}.{acl_dict['Error']['Endpoint']}"
            alibaba_api = f'https://{self.domain}/?acl'
            try:
                remote_acl = requests.get(alibaba_api, timeout=TIMEOUT, verify=False, headers=USER_AGENT).text
            except:
                if(verbose):
                    print(f'[d]   ACL Error {self.domain}')
                return
            acl_dict = xmltodict.parse(remote_acl, dict_constructor=dict)

        if not self._read_s3_acl(acl_dict) and self.enable_write:
            self.write_test()

    def _read_s3_acl(self, acl):
        if 'AccessControlPolicy' in acl:
            acl_rights = acl['AccessControlPolicy']['AccessControlList']
            if 'Grant' in acl_rights:
                self.acl = acl_rights['Grant']
                rights = {}
                if(type(self.acl) != list):
                    items = [self.acl]
                else:
                    items = self.acl

                for right in items:
                    if right['Grantee']['@xsi:type'] == 'CanonicalUser' and 'DisplayName' in right['Grantee']:
                        user = right['Grantee']['DisplayName']
                    elif right['Grantee']['@xsi:type'] == 'Group':
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
                    self.details.append(f'{user} [{symb}]')
            return True
        return False


class HiddenGems(object):

	HTTP_TIMEOUT = 5
	UA = { 'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36" }
	skip_extensions = ['exe','bin','pdf','zip','jpg','png','svg','avi','mp3','mp4','gz','tar','rar','7z','ttf','otf','woff','woff2']
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
	known_urls = []

	def __init__(self, url, deep=0, active_crawl=True):
		self.url = url
		self.childs = []
		self.urls = {}
		u = urlparse(url)
		self.scheme = u.scheme
		self.domain = u.netloc
		self.base_url = self.get_base_url(url)

		self.crawl(deep, active_crawl)

	def crawl(self, deep=0, active_crawl=False):
		try:
			self.known_urls.append(self.url)
			r = requests.get(self.url, timeout=self.HTTP_TIMEOUT, verify=False, headers=self.UA)
			if 'text/html' not in r.headers['Content-Type']: return False
		except:
			return False

		self.urls['js'] = self.extract_javascript(r.text)
		self.urls['links'] = self.extract_links(r.text)
		self.urls['styles'] = self.extract_styles(r.text)
		self.urls['images'] = self.extract_images(r.text)
		self.urls['forms'] = self.extract_forms(r.text)
		self.urls['cors'] = self.extract_cors(r.headers)

		if(active_crawl):
			self.urls['js-pluss'] = self.crawl_raw_urls(self.urls['js'])
			self.urls['styles-pluss'] = self.crawl_raw_urls(self.urls['styles'])
			files = [x for x in self.list_urls() if x.endswith('.json') or x.endswith('.xml')]
			self.urls['files'] = self.crawl_raw_urls(files)

		if(deep > 0):
			childs = self.filter_scope(list(set(self.urls['links'] + self.urls['forms'])))
			childs = [x for x in childs if self.url_extension(x) not in self.skip_extensions]
			for child in childs:
				if child not in self.known_urls:
					self.childs.append(HiddenGems(child, deep=deep - 1, active_crawl=active_crawl))

	def crawl_raw_urls(self, urls):
		result = []
		for url in urls:
			if url in self.known_urls:
				continue
			self.known_urls.append(url)
			if self.url_extension(url) in self.skip_extensions:
				continue
			try:
				r = requests.get(url, timeout=self.HTTP_TIMEOUT, verify=False, headers=self.UA)
				result += self.extract_raw_links(r.text)
			except:
				pass
		return result

	def get_base_url(self, url):
		u = urlparse(url)
		if(u.path):
			path = '/'.join(u.path.split('/')[:-1])
		else:
			path = u.path
		return f'{u.scheme}://{u.netloc}{path}'

	def filter_scope(self, values):
		return [x for x in values if self.domain == urlparse(x).netloc]

	def normalize_url(self, src, full_query=False, base_url=None):
		if not base_url:
			base_url = self.base_url
		url = urlparse(urljoin(base_url, src))
		if full_query and url.query:
			return f'{url.scheme}://{url.netloc}{url.path}?{url.query}'
		else:
			return f'{url.scheme}://{url.netloc}{url.path}'

	def url_extension(self, url):
		file = self.normalize_url(url).split('/')[-1]
		parts = file.split('.')
		if len(parts) == 1:
			return None
		return parts[-1].lower()

	def list_urls(self, scope=False, full_query=False):
		result = []
		for url_list in self.urls.values():
			for url in url_list:
				if url.startswith('http'):
					result.append(url)

		for child in self.childs:
			result += child.list_urls(scope)

		if(scope):
			result = self.filter_scope(result)

		result = [self.normalize_url(x, full_query) for x in result]
		result.sort()
		return list(set(result))

	def list_out_urls(self, full_query=False):
		return [x for x in self.list_urls(scope=False, full_query=full_query) if self.domain != urlparse(x).netloc]

	def list_dirs(self, scope=False):
		return list(set([self.get_base_url(x) for x in self.list_urls(scope)]))

	def list_out_dirs(self):
		return list(set([self.get_base_url(x) for x in self.list_out_urls()]))

	def list_domains(self):
		return list(set([urlparse(x).netloc for x in self.list_urls()]))

	def extract_javascript(self, source_code):
		tree = BeautifulSoup(source_code, 'html.parser')
		scripts = [self.normalize_url(s.get('src')) for s in tree.find_all('script') if s.get('src')]
		embedded_scripts = [s.text for s in tree.find_all('script') if not s.get('src')]
		for src in embedded_scripts:
			for url in re.findall(r'([\"\'])([\w\d\?\/&=\#\.\!_-]*?\.\w{2,4})(\1)', src):
				scripts.append(self.normalize_url(url[1]))
		return list(set(scripts))

	def extract_links(self, source_code):
		tree = BeautifulSoup(source_code, 'html.parser')
		hrefs = [self.normalize_url(s.get('href'), True) for s in tree.find_all('a') if s.get('href')]
		return list(set(hrefs))

	def extract_images(self, source_code):
		tree = BeautifulSoup(source_code, 'html.parser')
		imgs = [self.normalize_url(s.get('src')) for s in tree.find_all('img') if s.get('src')]
		return list(set(imgs))

	def extract_raw_links(self, source_code):
		urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[/?=\-_@.&+]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', source_code)
		return list(set(urls))

	def extract_styles(self, source_code):
		tree = BeautifulSoup(source_code, 'html.parser')
		hrefs = [self.normalize_url(s.get('href')) for s in tree.find_all('link') if s.get('href')]
		embedded_styles = [s.text for s in tree.find_all('link') if not s.get('href')]
		for src in embedded_styles:
			for url in re.findall(r'([\"\'])([\w\d\?\/&=\#\.\!_-]*?\.\w{2,4})(\1)', src):
				hrefs.append(self.normalize_url(url[1]))
		return list(set(hrefs))

	def extract_forms(self, source_code):
		tree = BeautifulSoup(source_code, 'html.parser')
		hrefs = [self.normalize_url(s.get('action'), True) for s in tree.find_all('form') if s.get('action')]
		return list(set(hrefs))

	def extract_cors(self, headers):
		cors = []
		if hasattr(headers, 'Access-Control-Allow-Origin'):
			cors = headers['Access-Control-Allow-Origin'].split(',')
			if '*' in cors: return []
		return cors


def generate_permutations(base_name, dict_file):
    p = [base_name]
    rules = ['{}-{}', '{}.{}', '{}{}']

    with open(dict_file, 'r') as f:
        lines = f.read().splitlines()

    for affix in lines:
        p += [x.format(affix, base_name) for x in rules]
        p += [x.format(base_name, affix) for x in rules]

    return p


def check_dns(hostname):
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.timeout = TIMEOUT
        resolver.lifetime = TIMEOUT
        resolver.nameservers = choices(dns_servers, k=2)
        answer = resolver.resolve(hostname)
        return answer[0].address if answer else False
    except:
        return False
    finally:
        del resolver


def check_host(host, ip):
    try:
        response = requests.head(f'http://{ip}', allow_redirects=True, timeout=TIMEOUT, verify=False, headers={'Host': host, **USER_AGENT})
    except:
        return False
    if response.status_code in [404, 400]:
        return False
    return response


def search_buckets(cloud_dict, names, cloud='generic', distribute=False, enable_write = False):
    queue = Queue(maxsize=0)
    results = []

    if distribute:
        srv_name = list(cloud_dict.keys())[0]
        srv_url = cycle(cloud_dict.values())
        for name in names:
            domain = f'{name}.{next(srv_url)}'
            queue.put((srv_name, domain, name))
    else:
        for srv_name, srv_url in cloud_dict.items():
            for name in names:
                domain = f'{name}.{srv_url}'
                queue.put((srv_name, domain, name))

    for w in range(num_threads):
        worker = Thread(target=search_buckets_worker, args=(queue, results, cloud, enable_write))
        worker.daemon = True
        worker.start()

    queue.join()
    return results


def search_buckets_worker(queue, results, cloud, enable_write):
    while not queue.empty():
        work = queue.get()
        srv_name = work[0]
        domain = work[1]
        name = work[2]

        # if(verbose):
        #     print(f'[d]   checking {domain}')

        ip = check_dns(domain)
        if ip:
            response = check_host(domain, ip)
            if(response != False or cloud == 'azure'):
                bucket = Bucket(name, domain, cloud, srv_name, enable_write)
                bucket.process_status(response)

                results.append(bucket)
                if not show_open_only or bucket.state == State.OPEN:
                    bucket.print_details()

        queue.task_done()

    return True


def what_cloud(urls, enable_write):
    queue = Queue(maxsize=0)
    results = []

    for url in urls:
        queue.put((url))

    for w in range(num_threads):
        worker = Thread(target=what_cloud_worker, args=(queue, results, enable_write))
        worker.daemon = True
        worker.start()

    queue.join()
    return results


def what_cloud_worker(queue, results, enable_write):
    while not queue.empty():
        url = queue.get()

        if(verbose):
            print(f'[d]   checking {url}')

        try:
            response = requests.head(url, allow_redirects=True, timeout=TIMEOUT, verify=False, headers=USER_AGENT)
        except:
            queue.task_done()
            continue

        fqdn = tldextract.extract(url).fqdn
        headers = response.headers.keys()

        if any(h in headers for h in ['x-amz-request-id', 'x-amz-id-2']) or any(n in fqdn for n in awsCloud.values()):
            cloud = 'aws'
        elif any(h in headers for h in ['X-GUploader-UploadID', 'x-goog-metageneration', 'X-Cloud-Trace-Context']) or any(n in fqdn for n in googleCloud.values()):
            if urlparse(url).netloc.endswith('.google.com'):
                queue.task_done()
                continue
            cloud = 'google'
        elif any(h in headers for h in ['x-ms-request-id']) or any(n in fqdn for n in azureCloud.values()):
            cloud = 'azure'
        elif any(h in headers for h in ['x-oss-request-id', 'x-oss-server-time']) or 'aliyuncs.com' in fqdn:
            cloud = 'alibaba'
        else:
            queue.task_done()
            continue

        srv_name = f'{cloud.capitalize()} Cloud'
        domain_name = tldextract.extract(url).domain
        u = urlparse(url)
        domain = u.netloc
        srv = u.path.split('/')[1:2]

        if len(domain.split('.')) > 3:
            name = domain.split('.')[0]
        elif not srv:
            name = domain_name
        elif domain_name in ['amazonaws','amazon','google','googleapis','appspot','azure','azureedge','windows','aliyuncs']:
            name = srv
        else:
            name = domain_name

        bucket = Bucket(name, url, cloud, srv_name, enable_write)
        bucket.process_status(response)

        results.append(bucket)
        if not show_open_only or bucket.state == State.OPEN:
            bucket.print_details()

        queue.task_done()


def show_banner():
    banner = f'''\033[0;32m
           ________                ____  __            __
          / ____/ /___  __  ______/ / / / /_  ______  / /____  _____
         / /   / / __ \/ / / / __  / /_/ / / / / __ \/ __/ _ \/ ___/
        / /___/ / /_/ / /_/ / /_/ / __  / /_/ / / / / /_/  __/ /
        \____/_/\____/\__,_/\__,_/_/ /_/\__,_/_/ /_/\__/\___/_/  v{__version__}
        \n\033[0;0m'''
    print(banner)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='CloudHunter. Searches for AWS, Azure and Google cloud storage buckets.')
    parser.add_argument('input', metavar='input', type=str, nargs='+', help='Company name, url or any base name.')
    parser.add_argument('-p', '--permutations-file', metavar='file', type=str, default='permutations.txt', help='Permutations file.')
    parser.add_argument('-s', '--services', metavar='aws,google,azure,alibaba', default='aws,google,azure,alibaba', help='specifies target services.')
    parser.add_argument('-w', '--write-test',  action='store_true', help='Enable write test to read rights when other methods fail.')
    parser.add_argument('-r', '--resolvers', metavar='file', type=str, default='resolvers.txt', help='DNS resolvers file.')
    parser.add_argument('-t', '--threads', metavar='num', type=int, default=10, help='Threads.')
    parser.add_argument('-c', '--crawl-deep', metavar='num', type=int, default=1, help='How many pages to crawl after the first.')
    parser.add_argument('-b', '--base-only',  action='store_true', help='Checks only the base name, skips permutations generation.')
    parser.add_argument('-d', '--disable-bruteforce',  action='store_true', help='Disable discovery by brute force.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose log')
    parser.add_argument('-o', '--open-only', action='store_true', help='Show only open buckets.')
    args = parser.parse_args()
    args.services = args.services.split(',')
    show_banner()

    num_threads = min(300, args.threads)
    show_open_only = args.open_only
    verbose = args.verbose
    with open(args.resolvers, 'r', encoding='utf-8') as f:
        dns_servers = f.read().splitlines()
    results = []

    if args.input[0].startswith('http'):
        url = args.input[0].strip().lower()
        base_name = tldextract.extract(url).domain

        print(f'[>] Crawling {url} ...')
        urls = [url]
        crawler = HiddenGems(url, args.crawl_deep)
        urls += crawler.list_out_dirs()

        print(f'[>] {len(urls)} possible endpoints found')
        results += what_cloud(urls, args.write_test)

    else:
        base_name = args.input[0].strip().lower()

    if(args.disable_bruteforce):
        exit(0)

    if(args.base_only):
        permutations = [base_name]
    else:
        permutations = generate_permutations(base_name, args.permutations_file)
    print(f'[>] Bruteforce {len(permutations)} name permutations.')

    if 'google' in args.services:
        print('\n[+] Check Google Cloud')
        results += search_buckets(googleCloud, permutations, 'google', False, args.write_test)

    if 'aws' in args.services:
        print('\n[+] Check Amazon Cloud')
        results += search_buckets(awsCloud, permutations, 'aws', False, args.write_test)

    if 'azure' in args.services:
        print('\n[+] Check Azure Cloud')
        results += search_buckets(azureCloud, permutations, 'azure', False, args.write_test)

    if 'alibaba' in args.services:
        print('\n[+] Check Alibaba Cloud')
        results += search_buckets(alibabaCloud, permutations, 'alibaba', True, args.write_test)

    output = [{
        'cloud': item.cloud,
        'name': item.name,
        'domain': item.domain,
        'state': item.state.value,
        'risk': item.risk.name,
        'details': item.details
    } for item in results]
    
    with open(f'{base_name}-output.json', 'w', encoding='utf-8') as f:
        json.dump(output, f, ensure_ascii=False, indent=2)
