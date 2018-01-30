# import libs as needed
import datetime
import requests
import gzip
import json
import hashlib
import hmac
import boto3

# Variables:

index_name = 'adi'
es_endpoint = '???.es.amazonaws.com'
region = 'us-east-1???'
access_key_id = 'access key id'
secret_access_key = 'secret access key'
method = 'POST'
service = 'es'
content_type = 'application/x-amz-json-1.0'

# Key derivation functions. See:
# http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-python
def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

def get_signature_key(key, dateStamp, regionName, serviceName):
    kDate = sign(('AWS4' + key).encode('utf-8'), dateStamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kregion, service_name)
    kSigning = sign(kService, 'aws4_request')
    return kSigning
	
s3 = boto3.client('s3')

# main function
def lambda_handler(event, context):
    print "Info: Event received."

    bucket = event['Records'][0]['s3']['bucket']['name']
    key = event['Records'][0]['s3']['object']['key']

    # download file from S3
    file_path = '/tmp/cloudtraillogfile.gz'
    s3.download_file(bucket, key, file_path)

    # open the compressed file for reading (no need to decompress in separate action)
    gzfile = gzip.open(file_path, "r")
    records = json.loads(gzfile.readlines()[0])["Records"]

    # read the events/records one by one and process them
    for r in records:
		print 'Info: Sending record to AWS ES service...'

		# adds @timestamp field = time of the event to make sure we have the
        # correct, event time in ES and not the ingestion time
		r["@timestamp"] = r["eventTime"]

		# removes .aws.amazon.com from eventsources
		#r["eventSource"] = r["eventSource"].split(".")[0]
		data = json.dumps(r)

		# create the index name based on eventTime (daily indexes)
		event_date = r["eventTime"].split("T")[0].replace("-", ".")

		# ES URL endpoint
		url_es_endpoint = 'https://' + es_endpoint + '/' + index_name + event_date + '/cloudtrail/'
		print "Info: ES URL endpoint is ", url_es_endpoint
		print "Info: Data is ", data

		t = datetime.datetime.utcnow()
		amz_date = t.strftime('%Y%m%dT%H%M%SZ')
		dateStamp = t.strftime('%Y%m%d')
		
		canonical_uri = '/' + index_name + event_date + '/cloudtrail/'
		# remove the below since it is empty, when everything works fine
		canonical_querystring = ''
		canonical_headers = 'content-type:' + content_type + '\n' + 'host:' + es_endpoint + '\n' + 'x-amz-date:' + amz_date + '\n'		
		signed_headers = 'content-type;host;x-amz-date'
		
		payload_hash = hashlib.sha256(data).hexdigest()
		
		canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash
		algorithm = 'AWS4-HMAC-SHA256'
		credential_scope = dateStamp + '/' + region + '/' + service + '/' + 'aws4_request'
		string_to_sign = algorithm + '\n' + amz_date + '\n' + credential_scope + '\n' + hashlib.sha256(canonical_request).hexdigest()
		signing_key = get_signature_key(secret_access_key, dateStamp, region, service)
		signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
		authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ',' + 'SignedHeaders=' + signed_headers + ',' + 'Signature=' + signature
		headers = {'Content-Type':content_type,'X-Amz-Date':amz_date,'Authorization':authorization_header}

		# post to ES
		req = requests.post(url_es_endpoint, data=data, headers=headers)

		print "Info: Status code ", req.status_code
		print "Info: ", req.text

		# make sure events are not lost; if post not successful, try again
        attempts_max = 4
		attempts_counter = 1
		while req.status_code != 201 and attempts_counter < attempts_max:
			print "Warning: Attempt " + attempts_counter + " of " + attempts_max + " failed: ", req.status_code
			print "Info: trying again..."
			req = requests.post(url_es_endpoint, data=data, headers=headers)
			
			if req.status_code == 201:
				print "Success: Data successfully sent!"
			
			print "Info: Status code ", req.status_code
			print "Info: ", req.text
			attempts_counter += 1

    print "Success: All done!"
