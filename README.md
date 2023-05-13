# CloudHunter
Looks for AWS, Azure, Alibaba and Google cloud storage buckets and lists permissions for vulnerable buckets.

## Usage

` python3 cloudhunter.py --permutations-file permutations-big.txt COMPANY_NAME `

` python3 cloudhunter.py --services aws,alibaba COMPANY_NAME `

` python3 cloudhunter.py --threads 50 http://example.com `

` python3 cloudhunter.py --write-test -s alibaba --open-only http://example.com `


### Help

```bash
usage: cloudhunter.py [-h] [-p file] [-s aws,google,azure,alibaba] [-w] [-r file] [-t num] [-c num] [-b] [-d] [-v] [-o] input

positional arguments:
  input                          Company name, url or any base name.

options:
  -h, --help                     show this help message and exit
  -p, --permutations-file file   Permutations file.
  -s, --services aws,google,azure,alibaba   Specifies target services.
  -w, --write-test               Enable write test to read rights when other methods fail.
  -r, --resolvers file           DNS resolvers file.
  -t, --threads num              Threads.
  -c, --crawl-deep num           How many pages to crawl after the first.
  -b, --base-only                Checks only the base name, skips permutations generation.
  -d, --disable-bruteforce       Disable discovery by brute force.
  -v, --verbose                  Verbose log.
  -o, --open-only                Show only open buckets.
```


## Output

```bash
 python3 cloudhunter.py -t 10 http://example.com

           ________                ____  __            __
          / ____/ /___  __  ______/ / / / /_  ______  / /____  _____
         / /   / / __ \/ / / / __  / /_/ / / / / __ \/ __/ _ \/ ___/
        / /___/ / /_/ / /_/ / /_/ / __  / /_/ / / / / /_/  __/ /
        \____/_/\____/\__,_/\__,_/_/ /_/\__,_/_/ /_/\__/\___/_/


[>] Crawling http://example.com ...
[>] 61 possible endpoints found
    Azure Cloud           https://dmpcdn.files-example/cdn               PRIVATE
    Google Cloud          http://demo-site.org                           OPEN      Redirect https://demo-site.org/
    Google Cloud          https://other.net                              OPEN

[>] Bruteforce 1591 name permutations.

[+] Check Google Cloud
    Google Storage        example.storage.googleapis.com                 PRIVATE
    Google Storage        example-attachments.storage.googleapis.com     OPEN      AllUsers [LR]
    Google Storage        example-backups.storage.googleapis.com         PRIVATE
    Google Storage        examplestorage.storage.googleapis.com          OPEN      AllUsers [LRWV]
    Google Storage        examplestore.storage.googleapis.com            PRIVATE
    Google App Engine     example.bigtable.appspot.com                   OPEN      WebApp Error
    Google App Engine     example.beta.appspot.com                       OPEN
    Google App Engine     example.data-private.appspot.com               OPEN      Redirect https://accounts.google.com/ServiceLogin
	...
[+] Check Amazon Cloud
    AWS Bucket            examplefiles.s3.amazonaws.com                  OPEN      LIST
    AWS Bucket            finance-example.s3.amazonaws.com               PRIVATE
    AWS Bucket            examplejs.s3.amazonaws.com                     OPEN      gmantri [F] | AllUsers [RW]
    AWS Bucket            example-logs.s3.amazonaws.com                  PRIVATE
    AWS Bucket            example.media.s3.amazonaws.com                 OPEN      zectroxity [RW] | AllUsers [R]
    AWS Bucket            exampleresources.s3.amazonaws.com              PRIVATE
    AWS Bucket            s3-example.s3.amazonaws.com                    OPEN      develop [F] | AuthenticatedUsers [F] | df99361a [F]
    AWS Bucket            exampleshop.s3.amazonaws.com                   PRIVATE
    AWS Bucket            example-web.s3.amazonaws.com                   OPEN      42cf2125 [F]
	...
[+] Check Alibaba Cloud
    Alibaba Bucket        example-admin.oss-cn-hangzhou.aliyuncs.com     PRIVATE
    Alibaba Bucket        example-data.oss-cn-beijing.aliyuncs.com       OPEN      WRITE
    Alibaba Bucket        exampledemo.oss-cn-beijing.aliyuncs.com        OPEN      root [RW] | AllUsers [R]
    Alibaba Bucket        demo-example.oss-cn-shanghai.aliyuncs.com      PRIVATE
    Alibaba Bucket        example-demo.oss-cn-shenzhen.aliyuncs.com      OPEN      LIST
	...
[+] Check Azure Cloud
    Storage Files         example.file.core.windows.net                  PRIVATE
    App Management        example-demo.blob.core.windows.net             PRIVATE
    App Azure             githubexample.blob.core.windows.net            OPEN
    App Azure             exampletest.azurewebsites.net                  PRIVATE
    App Azure             jira-example.azurewebsites.net                 OPEN      Redirect https://jira-example.azurewebsites.net/
    App Azure             examplestats.azurewebsites.net                 OPEN
    Databases-MSSQL       example-project.database.windows.net           DOMAIN
    Email                 example.mail.protection.outlook.com            DOMAIN
    SharePoint            example.sharepoint.com                         PRIVATE   Redirect https://example.sharepoint.com/
	...
```

## Disclaimer

This tool provided is intended for legal and ethical use only. Any unauthorized or malicious use of this tool is strictly prohibited and may result in legal actions. The developers of this tool are not responsible for any misuse or damage caused by the tool. Use this tool at your own risk and with discretion and always obtain proper authorization before using this tool on any system or network that you do not own or have legal permission to test. The "write-test" option performs intrusive operations to determine bucket rights, use only with explicit authorization.


## Thanks

- [@brianwarehime](https://github.com/brianwarehime) ([inSp3ctor](https://github.com/brianwarehime/inSp3ctor))
- [@SpenGietz](https://github.com/SpenGietz) ([GCPBucketBrute](https://github.com/RhinoSecurityLabs/GCPBucketBrute))
- [@kfosaaen](https://github.com/kfosaaen) ([MicroBurst](https://github.com/NetSPI/MicroBurst))
- [@PatrikHudak](https://github.com/PatrikHudak) ([second-order](https://gist.github.com/PatrikHudak/2006c50a694cc76ead705c91805df78b))
