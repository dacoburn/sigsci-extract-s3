# sigsci-extract-s3

## Description

Simple script to show pulling information from the Signal Sciences API. This script will pull from the requests API but of course can be modified to pull from any API. The results from the API are automatically saved in a S3 Bucket. The sample shows saving it in a JSON format but this can be modified as desired.

## Usage

python sigsci-extract_s3.py --config conf.json

## Conf File Settings

| Key Name | Description |
|----------|-------------|
| email    | This is the e-mail of your Signal Sciences user |
| password | This is the password of your Signal Sciences user. If this is not provided you will need to use the API Token |
| apitoken | If this is provided it will be used INSTEAD of your password. If set you can leave password empty |
| corp_name | This is the API name of your corp. You can find it in one of the dashboard URLS |
| dash_sites | This is the array of API Names of your dashboard sites. You can put 1 or more in this list to pull data from multiple sites |
| deleta | This is the delta in minutes to pull data. Default is 5 and can be adjusted. Whatever your delta is, is how often you should run the script. You can not do a value less than 1 |
| aws_access_key | Your AWS S3 API Access Key |
| aws_secret_key | Your AWS S3 API Secret Key |
| bucket_name | Name of the Bucket to save your results in. default filename is `sitename_fromtime_untiltime.json` |

## Finding your Signal Sciences API Info

**CORP Name & Site Name**
You can find your Corp API Name and Site API Name in the dashboard URL. The `EXAMPLECORPNAME` would be the api name of your corp and and the `EXAMPLESITENAME` would be the api name of your site.

https://dashboard.signalsciences.net/corps/EXAMPLECORPNAME/sites/EXAMPLESITENAME/

So lets say my corp API name is `foocorp` and my Dashboard Site API Name is `barsite` then the URL woudl look like:

https://dashboard.signalsciences.net/corps/foocorp/sites/barsite/

**API Tokens**

Information on getting your API Token can be found at https://docs.signalsciences.net/using-signal-sciences/using-our-api/

