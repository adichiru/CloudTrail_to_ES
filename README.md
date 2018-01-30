# CloudTrail_to_ES
A python lambda function for inserting CloudTrail logs into the AWS ES service.

## Requirements
1. An access key with the correct permissions
2. CloudTrail needs to be configured to upload logs into an S3 bucket.
3. The S3 bucket needs to have a trigger that will call a lambda function (the one in this project) when new files are uploaded/created in the bucket.


## Note
For URL Signing, the code was taken from:

http://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html

## Logic
This script:
1. Receives an S3 event (the new file uploaded to S3)
2. Downloads the file from S3
3. Unpacks it and inserts its json contents into the AWS ES service
(it automatically creates an index for each day in the format [index_name]-YYYY.MM.DD)

## To do
- use a lambda role defined in IAM to replace the need for keys in this script
- add logging capabilities instead of priting to stoud.
- extract the URL signature to a separate function (if possible)
- raise exceptions (this would require logic for storing the position in the file to avoid duplication and missing events)
