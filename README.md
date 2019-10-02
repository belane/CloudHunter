# CloudHunter
Looks for AWS, Azure and Google cloud storage buckets and lists permissions for vulnerable buckets.

## Usage
```
usage: cloudhunter.py [-h] [-p file] [-t num] [-b] [-v] [-o] basename


positional arguments:
  basename              Company name or any base name.

optional arguments:
  -h, --help            show this help message and exit
  -p file, --permutations-file  Permutations file.
  -t num, --threads 	Threads.
  -b, --base-only       checks only the base name, skips permutations generation.
  -v, --verbose         verbose log
  -o, --open-only       show only open buckets.

```

## Output
```
 python3 cloudhunter.py -t 10 example

           ________                ____  __            __
          / ____/ /___  __  ______/ / / / /_  ______  / /____  _____
         / /   / / __ \/ / / / __  / /_/ / / / / __ \/ __/ _ \/ ___/
        / /___/ / /_/ / /_/ / /_/ / __  / /_/ / / / / /_/  __/ /
        \____/_/\____/\__,_/\__,_/_/ /_/\__,_/_/ /_/\__/\___/_/


[>] 1591 name permutations.
[>] 33411 tries, be patient.


[+] Check Google Cloud
    Google Storage        example.storage.googleapis.com                 PRIVATE
    Google Storage        example-api.storage.googleapis.com             PRIVATE
    Google Storage        example-attachments.storage.googleapis.com     OPEN      AllUsers [LR]
    Google Storage        example-backups.storage.googleapis.com         PRIVATE
    Google Storage        examplestorage.storage.googleapis.com          OPEN      AllUsers [LRWV]
    Google Storage        examplestore.storage.googleapis.com            PRIVATE
    Google App Engine     example.bigtable.appspot.com                   OPEN      WebApp Error
    Google App Engine     example.beta.appspot.com                       OPEN
    Google App Engine     example.data-private.appspot.com               OPEN      Redirect https://accounts.google.com/ServiceLogin
	...
[+] Check Amazon Cloud
    AWS Bucket            examplefiles.s3.amazonaws.com                  OPEN      
    AWS Bucket            finance-example.s3.amazonaws.com               PRIVATE   
    AWS Bucket            examplejs.s3.amazonaws.com                     OPEN      gmantri [F] | AllUsers [RW]
    AWS Bucket            example-logs.s3.amazonaws.com                  PRIVATE   
    AWS Bucket            examplemedia.s3.amazonaws.com                  PRIVATE   
    AWS Bucket            example.media.s3.amazonaws.com                 OPEN      zectroxity [RW] | AllUsers [R]
    AWS Bucket            exampleprod.s3.amazonaws.com                   PRIVATE   
    AWS Bucket            exampleresources.s3.amazonaws.com              PRIVATE   
    AWS Bucket            s3-example.s3.amazonaws.com                    OPEN      develop [F] | AuthenticatedUsers [F] | df99361a [F]
    AWS Bucket            exampleshop.s3.amazonaws.com                   PRIVATE   
    AWS Bucket            example-web.s3.amazonaws.com                   OPEN      42cf2125 [F]
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
