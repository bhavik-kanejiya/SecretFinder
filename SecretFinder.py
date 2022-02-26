#!/usr/bin/env python 
# SecretFinder - Tool for discover apikeys/accesstokens and sensitive data in js file
# based to LinkFinder - github.com/GerbenJavado
# By m4ll0k (@m4ll0k2) github.com/m4ll0k


import os,sys
if not sys.version_info.major >= 3:
    print("[ + ] Run this tool with python version 3.+")
    sys.exit(0)
# os.environ["BROWSER"] = "open"

import re
import glob
import argparse 
import jsbeautifier 
import webbrowser
import subprocess 
import base64
import requests 
import string 
import random 
from html import escape
import urllib3
import xml.etree.ElementTree

# disable warning

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# for read local file with file:// protocol
from requests_file import FileAdapter
from lxml import html
from urllib.parse import urlparse

# regex 
_regex = {
        'Accengage Partner ID and Private Key' : r'\"acc_private_key\"\>[0\-9a\-f]{40}',
        'amazon_aws_url' : r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
        'amazon_mws_auth_toke' : r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        'Artifactory Token'  : r"artifactory.{0,50}(\\\"|'|`)?[a-zA-Z0-9=]{112}(\\\"|'|`)?",
        'Artifactory'  : r"(?i)artifactory.{0,50}(\\\"|'|`)?[a-zA-Z0-9=]{112}(\\\"|'|`)?",
        'ATOMIST_API_KEY' : r'\b[A-F0-9]{64}\b/',
        'Authorization Header' : r'^(Bearer|Basic) [a-zA-Z0-9_\-\.=:_\+\/]{5,100}',
        'AWS API Gateway'  : r'[0-9a-z]+\.execute-api\.[\w\.-]+\.amazonaws\.com',
        'AWS ARN'  : r'arn:aws:[a-z0-9-]+:[a-z]{2}-[a-z]+-[0-9]+:[0-9]+(?<!(123456789012|000000000000)):.+',
        'AWS Client ID'  : r'(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
        'amazon_aws_access_key_id' : r'A[SK]IA[0-9A-Z]{16}',
        'AWS EC2 External'  : r'ec2-[\w\.-]+\.compute(-1)?\.amazonaws\.com',
        'AWS EC2 Internal'  : r'domu-[\w\.-]+\.compute(-1)?\.internal',
        'AWS ElasticCache'  : r'[\w\.-]+\.cache\.amazonaws\.com',
        'AWS ElasticSearch'  : r'[\w\.-]+\.es\.amazonaws\.com',
        'AWS ELB'  : r'[\w\.-]+\.elb\.[\w\.-]+\.amazonaws\.com',
        'AWS MWS key'  : r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        'AWS RDS'  : r'[\w\.-]+\.rds\.amazonaws\.com',
        'AWS S3 Bucket'  : r's3://[0-9a-zA-Z.\-_/]+',
        'AWS S3 Endpoint'  : r'[\w\.-]+\.s3\.amazonaws\.com',
        'AWS S3 Website Endpoint'  : r'[\w\.-]+\.s3-website[\w\.-]+\.amazonaws\.com',
        'AWS Secret Key'  : r"aws(.{0,20})?['\"][0-9a-z\/+]{40}['\"]",
        'Braintree API Key'  : r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
        'Branch SDK Key' : r'key_live_[0\-9A\-Za\-z\-_\-]{32}',
        'Branch Secret Key' : r'secret_live_[0\-9A\-Za\-z\-_\-]{32}',
        'Cloudinary API Key/Secret Pair' : r'cloudinary://[0\-9]{15}:[0\-9A\-Za\-z\-_\-]{27}',
        'Cloudinary Basic Auth'  : r'(?i)cloudinary:\/\/[0-9]{15}:[0-9A-Za-z]+@[a-z]+',
        'CodeClimate Key'  : r"codeclima.{0,50}(\\\"|'|`)?[0-9a-f]{64}(\\\"|'|`)?",
        'Facebook Access Token'  : r'EAACEdEose0cBA[0-9a-z]+',
        'Facebook Client ID'  : r"(facebook|fb)(.{0,20})?['\"][0-9]{13,17}['\"]",
        'Facebook Secret Key'  : r"(facebook|fb)(.{0,20})?['\"][0-9a-f]{32}['\"]",
        'facebook access token' : r'EAACEdEose0cBA[0-9A-Za-z]+',
        'FCM server key' : r"AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}",
        'firebase'  : r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
        'GCP_Key' : r"(?i)(google|gcp|youtube|drive|yt)(.{0,20})?['\"][AIza[0\-9a\-z\\\-_]{35}]['\"]",
        'Github Access Token 2'  : r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\\-]+@github\\.com*',
        'GitHub Token'  : r"github(.{0,20})?['\"][0-9a-z]{35,40}['\"]",
        'Github Token 2' : r'(https?:\/\/)(?:v1\.)?[a-f0-9]{40}((?::x-oauth-basic)?@)',
        'Google (GCM) Service account'  : r"((\\\"|'|`)?type(\\\"|'|`)?\\\\s{0,50}(:|=>|=)\\\\s{0,50}(\\\"|'|`)?service_account(\\\"|'|`)?,?)",
        'Google API Key Base64'  : r'QUl6Y[%a-zA-Z0-9+/]{47}',
        'Google API Key'  : r'AIza[0-9a-zA-Z\-_]{35}',
        'Google Cloud Platform API key'  : r"(google|gcp|youtube|drive|yt)(.{0,20})?['\"][AIza[0-9a-z\\-_]{35}]['\"]",
        'Google OAuth Access Token'  : r'ya29\\.[0-9A-Za-z\\-_]+',
        'Google Oauth ID'  : r'[0-9]+-[0-9a-z_]{32}\.apps\.googleusercontent\.com',
        'Google Oauth'  : r"((\\\"|'|`)?client_secret(\\\"|'|`)?\\\\s{0,50}(:|=>|=)\\\\s{0,50}(\\\"|'|`)?[a-zA-Z0-9-_]{24}(\\\"|'|`)?)",
        'google_api'     : r'AIza[0-9A-Za-z-_]{35}',
        'google_oauth'   : r'ya29\.[0-9A-Za-z\-_]+',
        'GOOGLE_OAUTH_ID' : r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/',
        'heroku_api' : r'[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
        'HockeyApp API Key'  : r"hockey.{0,50}(\\\"|'|`)?[0-9a-f]{32}(\\\"|'|`)?",
        'JSON Web Token'  : r'ey[A-Za-z0-9_=-]+\\.ey[A-Za-z0-9_=-]+\\.?[A-Za-z0-9_.+/=-]*',
        'json_web_token' : r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
        'LinkedIn Client ID'  : r"(?i)linkedin(.{0,20})?(?-i)['\"][0-9a-z]{12}['\"]",
        'LinkedIn Secret Key' : r"(?i)linkedin(.{0,20})?['\"][0-9a-z]{16}['\"]",
        'Mailchimp API Key'  : r'[0-9a-f]{32}-us[0-9]{1,2}',
        'Mailgun API Key'  : r'key-[0-9a-zA-Z]{32}',
        'Mapbox Secret Access Token' : r'sk.ey[0\-9A\-Za\-z\-_.\-]{81}',
        'Microsoft Azure Tenant Client Secret' : r'[0\-9A\-Za\-z\+\=]{40\,50}',
        'New_Relic' : r'[0\-9a\-f]{36}NRAL',
        'Nuget API Key'  : r'(?i)oy2[a-z0-9]{43}',
        'Outlook Secrets'  : r'(https\\://outlook\\.office.com/webhook/[0-9a-f-]{36}\\@)',
        'PayPal Braintree Access Token'  : r'access_token\\$(live|production)\\$[0-9a-z]{16}\\$[0-9a-f]{32}', # extra
        'PGP'  : r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
        'pgp_private_block' : r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
        'Picatic API Key'  : r'sk_live_[0-9a-z]{32}',
        'Possible-Juicy-Files' : r"(aws_access|aws_secret|api[_-]?key|S3_ACCESS_KEY|aws_|secret)",
        'Private_Key' : r'([-]+BEGIN [^\\s]+ PRIVATE KEY[-]+[\\s]*[^-]*[-]+END [^\\s]+ PRIVATE KEY[-]+)',
        'RKCS8'  : r'-----BEGIN PRIVATE KEY-----',
        'RSA'  : r'-----BEGIN RSA PRIVATE KEY-----',
        'rsa_private_key' : r'-----BEGIN RSA PRIVATE KEY-----',
        'Sauce Token'  : r"sauce.{0,50}(\\\"|'|`)?[0-9a-f-]{36}(\\\"|'|`)?",
        'SendGrid API Key'  : r'SG\\.[\\w_]{16,32}\\.[\\w_]{16,64}',
        'SendGrid API Key 2' : r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
        'slack access token Bot' : r"xoxb-[0-9A-Za-z\\-]{51}",
        'slack access token Person' : r"xoxp-[0-9A-Za-z\\-]{72}",
        'Slack Token'  : r'(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})',
        'Slack Token 2'  : r'xox[baprs]-([0-9a-z-]{10,48})',
        'Slack Webhook'  : r'https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}',
        'slack_token' : r"\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"",
        'slack_token 2' : r'(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})',
        'slack_webhook' : r'https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
        'Sonar'  : r"(?i)sonar.{0,50}(\\\"|'|`)?[0-9a-f]{40}(\\\"|'|`)?",
        'SonarQube API Key'  : r"sonar.{0,50}(\\\"|'|`)?[0-9a-f]{40}(\\\"|'|`)?",
        'Square Access Token'  : r'sq0atp-[0-9A-Za-z\\-_]{22}',
        'Square API Token / Secret'  : r'sq0(atp|csp)-[0-9a-z\-_]{22,43}',
        'Square OAuth Secret'  : r'sq0csp-[0-9A-Za-z\\-_]{43}',
        'square_access_token' : r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}',
        'square_oauth_secret' : r'sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',
        'SSH Password' : r"sshpass -p.*['|\\\"]",
        'SSH'  : r'-----BEGIN OPENSSH PRIVATE KEY-----',
        'ssh_dc_private_key' : r'-----BEGIN EC PRIVATE KEY-----',
        'ssh_dsa_private_key' : r'-----BEGIN DSA PRIVATE KEY-----',
        'SSH_privKey' : r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)",
        'StackHawk API Key'  : r'hawk\.[0-9A-Za-z\-_]{20}\.[0-9A-Za-z\-_]{20}',
        'Stripe API Key'  : r'sk_live_[0-9a-zA-Z]{24}',
        'Stripe Public Live Key'  : r'pk_live_[0-9a-z]{24}',
        'Stripe Public Test Key'  : r'pk_test_[0-9a-z]{24}',
        'Stripe Restricted API Key'  : r'rk_live_[0-9a-zA-Z]{24}',
        'Stripe Secret Live Key'  : r'(sk|rk)_live_[0-9a-z]{24}',
        'Stripe Secret Test Key'  : r'(sk|rk)_test_[0-9a-z]{24}',
        'stripe_token' : r'(?:r|s)k_[live|test]_[0-9a-zA-Z]{24}',
        'Surge'  : r"(?i)surge.{0,50}(\\\"|'|`)?[0-9a-f]{32}(\\\"|'|`)?",
        'Telegram Secret'  : r'\d{5,}:A[0-9a-z_\-]{34,34}',
        'Tenable key'  : r"(?i)['\"]?[a-z-_]*(tenable|nessus)[a-z-_]*['\"]?\\s*[=:]\\s*['\"]?\\w{64}['\"]?\\s*,?\\s*$",
        'Trello URL'  : r'https://trello.com/b/[0-9a-z]/[0-9a-z_-]+',
        'Twilio API Key'  : r'SK[0-9a-fA-F]{32}',
        'twilio_api_key' : r'SK[0-9a-fA-F]{32}',
        'Twitter Client ID'  : r"twitter(.{0,20})?['\"][0-9a-z]{18,25}['\"]",
        'Twitter Secret Key'  : r"twitter(.{0,20})?['\"][0-9a-z]{35,44}['\"]",
        'Twitter_ACCESS_TOKEN' : r"twitter.*[1-9][0-9]+-[0-9a-zA-Z]{40}",
        'URL_PASSWORD' : r'((?:ht|f|sm)tps?:\/\/[^:/?#\[\]@""<>{}|\\^``\s]+:)[^:/?#\[\]@""<>{}|\\^``\s]+@',
        'Username:Password' : r'\b((?:ht|f|sm)tps?:\/\/)[^:/?#\[\]@""<>{}|\\^``\s]+:[^:/?#\[\]@""<>{}|\\^``\s]+@',
        'WP-Config'  : r"define(.{0,20})?(DB_CHARSET|NONCE_SALT|LOGGED_IN_SALT|AUTH_SALT|NONCE_KEY|DB_HOST|DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|DB_NAME|DB_USER)(.{0,20})?['|\"].{10,120}['|\"]",
}

_template = '''
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <style>
       h1 {
          font-family: sans-serif;
       }
       a {
          color: #000;
       }
       .text {
          font-size: 16px;
          font-family: Helvetica, sans-serif;
          color: #323232;
          background-color: white;
       }
       .container {
          background-color: #e9e9e9;
          padding: 10px;
          margin: 10px 0;
          font-family: helvetica;
          font-size: 13px;
          border-width: 1px;
          border-style: solid;
          border-color: #8a8a8a;
          color: #323232;
          margin-bottom: 15px;
       }
       .button {
          padding: 17px 60px;
          margin: 10px 10px 10px 0;
          display: inline-block;
          background-color: #f4f4f4;
          border-radius: .25rem;
          text-decoration: none;
          -webkit-transition: .15s ease-in-out;
          transition: .15s ease-in-out;
          color: #333;
          position: relative;
       }
       .button:hover {
          background-color: #eee;
          text-decoration: none;
       }
       .github-icon {
          line-height: 0;
          position: absolute;
          top: 14px;
          left: 24px;
          opacity: 0.7;
       }
  </style>
  <title>LinkFinder Output</title>
</head>
<body contenteditable="true">
  $$content$$
  
  <a class='button' contenteditable='false' href='https://github.com/m4ll0k/SecretFinder/issues/new' rel='nofollow noopener noreferrer' target='_blank'><span class='github-icon'><svg height="24" viewbox="0 0 24 24" width="24" xmlns="http://www.w3.org/2000/svg">
  <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22" fill="none" stroke="#000" stroke-linecap="round" stroke-linejoin="round" stroke-width="2"></path></svg></span> Report an issue.</a>
</body>
</html>
'''

def parser_error(msg):
    print('Usage: python %s [OPTIONS] use -h for help'%sys.argv[0])
    print('Error: %s'%msg)
    sys.exit(0)

def getContext(matches,content,name,rex='.+?'):
    ''' get context '''
    items = []
    matches2 =  []
    for  i in [x[0] for x in matches]:
        if i not in matches2:
            matches2.append(i)
    for m in matches2:
        context = re.findall('%s%s%s'%(rex,m,rex),content,re.IGNORECASE)

        item = {
            'matched'          : m,
            'name'             : name,
            'context'          : context,
            'multi_context'    : True if len(context) > 1 else False
        } 
        items.append(item)
    return items


def parser_file(content,mode=1,more_regex=None,no_dup=1):
    ''' parser file '''
    if mode == 1:
        if len(content) > 1000000:
            content = content.replace(";",";\r\n").replace(",",",\r\n")
        else:
            content = jsbeautifier.beautify(content)
    all_items = []
    for regex in _regex.items():
        r = re.compile(regex[1],re.VERBOSE|re.I)
        if mode == 1:
            all_matches = [(m.group(0),m.start(0),m.end(0)) for m in re.finditer(r,content)]
            items = getContext(all_matches,content,regex[0])
            if items != []:
                all_items.append(items)
        else:
            items = [{
                'matched' : m.group(0),
                'context' : [],
                'name'    : regex[0],
                'multi_context' : False
            } for m in re.finditer(r,content)]
        if items != []:
            all_items.append(items)
    if all_items != []:
        k = []
        for i in range(len(all_items)):
            for ii in all_items[i]:
                if ii not in k:
                    k.append(ii)
        if k != []:
            all_items = k

    if no_dup:
        all_matched = set()
        no_dup_items = []
        for item in all_items:
            if item != [] and type(item) is dict:
                if item['matched'] not in all_matched:
                    all_matched.add(item['matched'])
                    no_dup_items.append(item)
        all_items = no_dup_items

    filtered_items = []
    if all_items != []:
        for item in all_items:
            if more_regex:
                if re.search(more_regex,item['matched']):
                    filtered_items.append(item)
            else:
                filtered_items.append(item)
    return filtered_items
        

def parser_input(input):
    ''' Parser Input '''
    # method 1 - url 
    schemes = ('http://','https://','ftp://','file://','ftps://')
    if input.startswith(schemes):
        return [input]
    # method 2 - url inpector firefox/chrome
    if input.startswith('view-source:'):
        return [input[12:]]
    # method 3 - Burp file
    if args.burp:
        jsfiles = []
        items = []

        try:
            items = xml.etree.ElementTree.fromstring(open(args.input,'r').read())
        except Exception as err:
            print(err)
            sys.exit()
        for item in items:
            jsfiles.append(
                {
                    'js': base64.b64decode(item.find('response').text).decode('utf-8','replace'),
                    'url': item.find('url').text
                }
            )
        return jsfiles
    # method 4 - folder with a wildcard
    if '*' in input:
        paths = glob.glob(os.path.abspath(input))
        for index, path in enumerate(paths):
            paths[index] = "file://%s" % path
        return (paths if len(paths)> 0 else parser_error('Input with wildcard does not match any files.'))
        
    # method 5 - local file 
    path = "file://%s"% os.path.abspath(input)
    return [path if os.path.exists(input) else parser_error('file could not be found (maybe you forgot to add http/https).')]


def html_save(output):
    ''' html output '''
    hide = os.dup(1)
    os.close(1)
    os.open(os.devnull,os.O_RDWR)
    try:
        text_file = open(args.output,"wb")
        text_file.write(_template.replace('$$content$$',output).encode('utf-8'))
        text_file.close()
        
        print('URL to access output: file://%s'%os.path.abspath(args.output))
        file = 'file:///%s'%(os.path.abspath(args.output))
        if sys.platform == 'linux' or sys.platform == 'linux2':
            subprocess.call(['xdg-open',file])
        else:
            webbrowser.open(file) 
    except Exception as err:
        print('Output can\'t be saved in %s due to exception: %s'%(args.output,err))
    finally:
        os.dup2(hide,1)

def cli_output(matched):
    ''' cli output '''
    for match in matched:
        print(match.get('name')+'\t->\t'+match.get('matched').encode('ascii','ignore').decode('utf-8'))

def urlParser(url):
    ''' urlParser ''' 
    parse = urlparse(url)
    urlParser.this_root = parse.scheme + '://' + parse.netloc 
    urlParser.this_path = parse.scheme + '://' + parse.netloc  + '/' + parse.path

def extractjsurl(content,base_url):
    ''' JS url extract from html page '''
    soup = html.fromstring(content)
    all_src = []
    urlParser(base_url)
    for src in soup.xpath('//script'):
        src = src.xpath('@src')[0] if src.xpath('@src') != [] else [] 
        if src != []:
            if src.startswith(('http://','https://','ftp://','ftps://')):
                if src not in all_src:
                    all_src.append(src)
            elif src.startswith('//'):
                src = 'http://'+src[2:]
                if src not in all_src:
                    all_src.append(src)
            elif src.startswith('/'):
                src = urlParser.this_root + src 
                if src not in all_src:
                    all_src.append(src)
            else:
                src = urlParser.this_path + src 
                if src not in all_src:
                    all_src.append(src)
    if args.ignore and all_src != []:
        temp = all_src 
        ignore = []
        for i in args.ignore.split(';'):
            for src in all_src:
                if i in src:
                    ignore.append(src)
        if ignore:
            for i in ignore:
                temp.pop(int(temp.index(i)))
        return temp 
    if args.only:
        temp = all_src 
        only = []
        for i in args.only.split(';'):
            for src in all_src:
                if i in src:
                    only.append(src)
        return only 
    return all_src

def send_request(url):
    ''' Send Request ''' 
    # read local file 
    # https://github.com/dashea/requests-file
    if 'file://' in url:
        s = requests.Session()
        s.mount('file://',FileAdapter())
        return s.get(url).content.decode('utf-8','replace')
    # set headers and cookies
    headers = {}
    default_headers = {
        'User-Agent'      : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
        'Accept'          : 'text/html, application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language' : 'en-US,en;q=0.8',
        'Accept-Encoding' : 'gzip'
    }
    if args.headers:
        for i in args.header.split('\\n'):
            # replace space and split
            name,value = i.replace(' ','').split(':')
            headers[name] = value 
    # add cookies
    if args.cookie:
        headers['Cookie'] = args.cookie

    headers.update(default_headers)
    # proxy 
    proxies = {}
    if args.proxy:
        proxies.update({
            'http'  : args.proxy,
            'https' : args.proxy,
            # ftp 
        })
    try:
        resp = requests.get(
            url = url,
            verify = False,
            headers = headers, 
            proxies = proxies
        )
        return resp.content.decode('utf-8','replace')
    except Exception as err:
        print(err)
        sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-e","--extract",help="Extract all javascript links located in a page and process it",action="store_true",default=False)
    parser.add_argument("-i","--input",help="Input a: URL, file or folder",required="True",action="store")
    parser.add_argument("-o","--output",help="Where to save the file, including file name. Default: output.html",action="store", default="output.html")
    parser.add_argument("-r","--regex",help="RegEx for filtering purposes against found endpoint (e.g: ^/api/)",action="store")
    parser.add_argument("-b","--burp",help="Support burp exported file",action="store_true")
    parser.add_argument("-c","--cookie",help="Add cookies for authenticated JS files",action="store",default="")
    parser.add_argument("-g","--ignore",help="Ignore js url, if it contain the provided string (string;string2..)",action="store",default="")
    parser.add_argument("-n","--only",help="Process js url, if it contain the provided string (string;string2..)",action="store",default="")
    parser.add_argument("-H","--headers",help="Set headers (\"Name:Value\\nName:Value\")",action="store",default="")
    parser.add_argument("-p","--proxy",help="Set proxy (host:port)",action="store",default="")
    args = parser.parse_args()

    if args.input[-1:] == "/":
        # /aa/ -> /aa
        args.input = args.input[:-1]
    
    mode = 1 
    if args.output == "cli":
        mode = 0
    # add args
    if args.regex:
        # validate regular exp
        try:
            r = re.search(args.regex,''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(random.randint(10,50))))
        except Exception as e:
            print('your python regex isn\'t valid')
            sys.exit()

        _regex.update({
            'custom_regex' : args.regex
        })

    if args.extract:
        content = send_request(args.input)
        urls = extractjsurl(content,args.input)
    else:
        # convert input to URLs or JS files
        urls = parser_input(args.input)
    # conver URLs to js file
    output = '' 
    for url in urls:
        print('[ + ] URL: '+url)
        if not args.burp:
            file = send_request(url)
        else:
            file = url.get('js')
            url = url.get('url')
        
        matched = parser_file(file,mode)
        if args.output == 'cli':
            cli_output(matched)
        else:
            output += '<h1>File: <a href="%s" target="_blank" rel="nofollow noopener noreferrer">%s</a></h1>'%(escape(url),escape(url))
            for match in matched:
                _matched = match.get('matched')
                _named = match.get('name')
                header = '<div class="text">%s'%(_named.replace('_',' '))
                body = ''
                # find same thing in multiple context
                if match.get('multi_context'):
                    # remove duplicate
                    no_dup = []
                    for context in match.get('context'):
                        if context not in no_dup:
                            body += '</a><div class="container">%s</div></div>'%(context)
                            body = body.replace(
                                context,'<span style="background-color:yellow">%s</span>'%context)
                            no_dup.append(context)
                        # --
                else:
                    body += '</a><div class="container">%s</div></div>'%(match.get('context')[0] if len(match.get('context'))>1 else match.get('context'))
                    body = body.replace(
                        match.get('context')[0] if len(match.get('context')) > 0 else ''.join(match.get('context')),
                        '<span style="background-color:yellow">%s</span>'%(match.get('context') if len(match.get('context'))>1 else match.get('context'))
                    )
                output += header + body 
    if args.output != 'cli':
        html_save(output)
