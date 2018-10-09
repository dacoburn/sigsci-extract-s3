# encoding = utf-8
import time
# import datetime
from datetime import datetime, timedelta
import json
import calendar
import requests
import os
import argparse
from timeit import default_timer as timer
import boto3
# from decimal import Decimal

start = timer()

parser = argparse.ArgumentParser()
parser = argparse.ArgumentParser(description="Example script to pull data " +
                                 "from Signal Sciences and save to AWS S3")
parser.add_argument("--config", type=str,
                    help="Specify the file with the configuration options")

opts = parser.parse_args()

# Initial setup

if "config" in opts and not(opts.config is None):
    confFile = open(opts.config, "r")
    confJson = json.load(confFile)
else:
    confJson = ""

# Logfile for the script
logFile = "sigsci-extract.log"

try:
    os.remove(logFile)
except OSError as e:
    # print("Failed to remove %s with: %s" % (logFile,e.strerror))
    pass


def logOut(msg):
    log = open(logFile, 'a')
    data = "%s: %s" % (datetime.now(), msg)
    log.write(data)
    log.write("\n")
    log.close
    print(msg)


def writeToS3(uploadMsg, uploadFileName):
    s3client = boto3.client(
        's3',
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key
    )
    logOut("Writing results to S3")
    outFormat = json.dumps(uploadMsg)
    s3client.put_object(Bucket=bucket_name, Key=uploadFileName, Body=outFormat)


# This is requried and is used for all API requests.
if "email" in confJson and confJson["email"] is not None:
    email = confJson["email"]
else:
    email = os.environ.get('SIGSCI_EMAIL')
    if email is None or email == "":
        logOut("email must be specified in conf file")
        exit()

if "corp_name" in confJson and confJson["corp_name"] is not None:
    corp_name = confJson["corp_name"]
else:
    corp_name = os.environ.get('SIGSCI_CORP')
    if corp_name is None or corp_name == "":
        logOut("corp_name must be specified in conf file")
        exit()

if "password" in confJson and confJson["password"] is not None:
    password = confJson["password"]
else:
    password = os.environ.get('SIGSCI_PASSWORD')

if "apitoken" in confJson and confJson["apitoken"] is not None:
    apitoken = confJson["apitoken"]
else:
    apitoken = os.environ.get('SIGSCI_TOKEN')
    if (apitoken is None or apitoken == "") and \
            (password is None or password == ""):
        logOut("apitoken or password must be specified in conf file")
        exit()

if "dash_sites" in confJson and confJson["dash_sites"] is not None:
    dash_sites = confJson["dash_sites"]
else:
    dash_sites = os.environ.get('SIGSCI_SITES')
    if (dash_sites is None or dash_sites == ""):
        logOut("dash_sites must be specified in conf file")
        exit()

if "aws_access_key" in confJson and confJson["aws_access_key"] is not None:
    aws_access_key = confJson["aws_access_key"]
else:
    aws_access_key = os.environ.get('SIGSCI_AWS_ACCESS')
    if (aws_access_key is None or aws_access_key == ""):
        logOut("aws_access_key must be specified in conf file " +
               "for S3 access")
        logOut("Defaulting to writing to Log File")

if "aws_secret_key" in confJson and confJson["aws_secret_key"] is not None:
    aws_secret_key = confJson["aws_secret_key"]
else:
    aws_secret_key = os.environ.get('SIGSCI_AWS_SECRET')
    if (aws_secret_key is None or aws_secret_key == ""):
        logOut("aws_secret_key must be specified in conf file " +
               "for S3 access")
        logOut("Defaulting to writing to Log File")

if "bucket_name" in confJson and confJson["bucket_name"] is not None:
    bucket_name = confJson["bucket_name"]
else:
    bucket_name = os.environ.get('SIGSCI_BUCKET_NAME')
    if (bucket_name is None or bucket_name == ""):
        logOut("bucket_name must be specified in conf file " +
               "for S3 access")
        logOut("Defaulting to writing to Log File")

if "delta" in confJson and confJson["delta"] is not None:
    delta = int(confJson["delta"])
else:
    delta = os.environ.get('delta')
    if delta is None or delta == "":
        delta = 5

api_host = 'https://dashboard.signalsciences.net'

logOut("email: %s" % email)
logOut("corp: %s" % corp_name)
if apitoken is not None:
    logOut("Using API TOKEN")
else:
    logOut("Using Password Auth")

pythonRequestsVersion = requests.__version__
userAgentVersion = "1.0.0"
userAgentString = "SigSci-Extract-Example/%s (PythonRequests %s)" \
    % (userAgentVersion, pythonRequestsVersion)


# Definition for error handling on the response code

def checkResponse(code, responseText, curSite=None,
                  from_time=None, until_time=None):
    site_name = curSite
    if code == 400:
        if "Rate limit exceeded" in responseText:
            return("rate-limit")
        else:
            logOut("Bad API Request (ResponseCode: %s)" % (code))
            logOut("ResponseError: %s" % responseText)
            logOut('from: %s' % from_time)
            logOut('until: %s' % until_time)
            logOut('email: %s' % email)
            logOut('Corp: %s' % corp_name)
            logOut('SiteName: %s' % site_name)
            return("bad-request")
    elif code == 500:
        logOut(
            "Caused an Internal Server error (ResponseCode: %s)" % (code))
        logOut("ResponseError: %s" % responseText)
        logOut('from: %s' % from_time)
        logOut('until: %s' % until_time)
        logOut('email: %s' % email)
        logOut('Corp: %s' % corp_name)
        logOut('SiteName: %s' % site_name)
        return("internal-error")
    elif code == 401:
        logOut(
            "Unauthorized, likely bad credentials or site configuration," +
            " or lack of permissions (ResponseCode: %s)" % (code))
        logOut("ResponseError: %s" % responseText)
        logOut('email: %s' % email)
        logOut('Corp: %s' % corp_name)
        logOut('SiteName: %s' % site_name)
        return("unauthorized")
    elif code >= 400 and code <= 599 and code != 400 \
            and code != 500 and code != 401:
        logOut("ResponseError: %s" % responseText)
        logOut('from: %s' % from_time)
        logOut('until: %s' % until_time)
        logOut('email: %s' % email)
        logOut('Corp: %s' % corp_name)
        logOut('SiteName: %s' % site_name)
        return("other-error")
    else:
        return("success")


def sigsciAuth():
    logOut("Authenticating to SigSci API")
    # Authenticate
    authUrl = api_host + '/api/v0/auth'
    authHeader = {
        "User-Agent": userAgentString
    }
    auth = requests.post(
        authUrl,
        data={"email": email, "password": password},
        headers=authHeader
    )

    authCode = auth.status_code
    authError = auth.text

    authResult = checkResponse(authCode, authError)
    if authResult is None or authResult != "success":
        logOut("API Auth Failed")
        logOut(authResult)
        exit()
    elif authResult is not None and authResult == "rate-limit":
        logOut("SigSci Rate Limit hit")
        logOut("Retrying in 10 seconds")
        time.sleep(10)
        sigsciAuth()
    else:
        parsed_response = auth.json()
        token = parsed_response['token']
        logOut("Authenticated")
        return(token)


def getRequestData(url, headers):
    method = "GET"
    response_raw = requests.request(method, url, headers=headers)
    responseCode = response_raw.status_code
    responseError = response_raw.text
    return(response_raw, responseCode, responseError)


def pullRequests(curSite, delta, token, key=None, apiMode=None):
    site_name = curSite
    until_time = datetime.utcnow() - timedelta(minutes=5)
    until_time = until_time.replace(second=0, microsecond=0)
    from_time = until_time - timedelta(minutes=delta)
    until_time = calendar.timegm(until_time.utctimetuple())
    from_time = calendar.timegm(from_time.utctimetuple())
    from_pretty = \
        datetime.utcfromtimestamp(from_time).strftime('%Y-%m-%d %H:%M:%S')
    until_pretty = \
        datetime.utcfromtimestamp(until_time).strftime('%Y-%m-%d %H:%M:%S')

    logOut("SiteName: %s" % site_name)
    logOut("From: %s" % (from_pretty))
    logOut("Until: %s" % (until_pretty))

    # Loop across all the data and output it in one big JSON object
    if apiMode == "apitoken":
        headers = {
            'Content-type': 'application/json',
            'x-api-user': email,
            'x-api-token': apitoken,
            'User-Agent': userAgentString
        }
    else:
        headers = {
            'Content-type': 'application/json',
            'Authorization': 'Bearer %s' % token,
            'User-Agent': userAgentString
        }

    url = api_host + \
        ('/api/v0/corps/%s/sites/%s/feed/requests?from=%s&until=%s'
            % (corp_name, site_name, from_time, until_time))
    loop = True

    counter = 1
    logOut("Pulling requests from requests API")
    allRequests = []
    while loop:
        logOut("Processing page %s" % counter)
        startPage = timer()
        responseResult, responseCode, ResponseError = \
            getRequestData(url, headers)

        sigSciRequestCheck = \
            checkResponse(responseCode, ResponseError, curSite=site_name,
                          from_time=from_time, until_time=until_time)

        if sigSciRequestCheck is None or sigSciRequestCheck != "success":
            logOut("Failed to pull results")
            logOut(sigSciRequestCheck)
            exit()
        elif sigSciRequestCheck is not None and \
                sigSciRequestCheck == "rate-limit":
            logOut("SigSci Rate Limit hit")
            logOut("Retrying in 10 seconds")
            time.sleep(10)
            break
        else:
            response = json.loads(responseResult.text)

        curPageNumRequests = len(response['data'])
        logOut("Number of Requests for Page: %s" % curPageNumRequests)

        for request in response['data']:
            data = json.dumps(request)
            data = json.loads(data)
            headersFix = {}
            headersFix['headersOut'] = data['headersOut']
            headersFix['headersIn'] = data['headersIn']

            newFormatOut = {}

            if not (headersFix['headersOut'] is None):
                for out in headersFix['headersOut']:
                    newFormatOut[out[0]] = out[1]

                data['headersOut'] = newFormatOut

            newFormatIn = {}

            if not (headersFix['headersIn'] is None):
                for hIn in headersFix['headersIn']:
                    newFormatIn[hIn[0]] = hIn[1]

                data['headersIn'] = newFormatIn

            data = json.dumps(data)

            allRequests.append(data)

        if "next" in response and "uri" in response['next']:
            next_url = response['next']['uri']
            if next_url == '':
                logOut("Finished Page %s" % counter)
                counter += 1
                endPage = timer()
                pageTime = endPage - startPage
                pageTimeResult = round(pageTime, 2)
                logOut("Total Page Time: %s seconds" % pageTimeResult)
                loop = False
            else:
                url = api_host + next_url
                logOut("Finished Page %s" % counter)
                counter += 1
                endPage = timer()
                pageTime = endPage - startPage
                pageTimeResult = round(pageTime, 2)
                logOut("Total Page Time: %s seconds" % pageTimeResult)
        else:
            loop = False

    totalRequests = len(allRequests)
    logOut("Total Requests Pulled: %s" % totalRequests)
    writeStart = timer()

    from_s3 = \
        datetime.utcfromtimestamp(from_time).strftime('%Y_%m_%d-%H-%M-%S')
    until_s3 = \
        datetime.utcfromtimestamp(until_time).strftime('%Y_%m_%d-%H-%M-%S')
    s3FileName = "{}_{}_TO_{}.json".format(site_name, from_s3, until_s3)
    if aws_access_key is None or aws_secret_key is None or bucket_name is None:
        for curEvent in allRequests:
            logOut(curEvent)
    else:
        writeToS3(allRequests, s3FileName)
    writeEnd = timer()
    writeTime = writeEnd - writeStart
    writeTimeResult = round(writeTime, 2)
    logOut("Total Event Output Time: %s seconds" % writeTimeResult)


if apitoken is not None and apitoken != "":
    authMode = "apitoken"
    logOut("AuthMode: API Token")
else:
    authMode = "password"
    logOut("AuthMode: Password")
    sigsciToken = sigsciAuth()


for activeInput in dash_sites:
    site = activeInput
    logOut("site: %s" % site)
    if authMode == "apitoken":
        pullRequests(key=activeInput, curSite=site, delta=delta,
                     token=apitoken, apiMode="apitoken")
    else:
        pullRequests(key=activeInput, curSite=site, delta=delta,
                     token=sigsciToken)
    logOut("Finished Pulling Requests for %s" % site)

end = timer()
totalTime = end - start
timeResult = round(totalTime, 2)
logOut("Total Script Time: %s seconds" % timeResult)
