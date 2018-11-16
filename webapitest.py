import base64
import datetime
import hashlib
import hmac
import re
import urllib
import json
from urllib.parse import urlparse
import requests

def make_auth_headers(key, secret, resource_path, body="", auth_method='KeyPair'):
	if auth_method == 'Basic':
		return {'Authorization': 'Basic ' + base64.b64encode(key + ':' + secret), 
			'URIPath': resource_path}

	if resource_path.find('v1.2', 5) > 1:
		print("Authentication")
		iso8601_timestamp = None
		utc = datetime.datetime.utcnow()
		dt = utc.strftime("%Y %m-%dT%H:%M:%S.000Z")
		h_secret = hmac.new(unicode(secret, 'utf-8'), unicode(secret, 'utf-8'), digestmod=hashlib.sha256).digest()

		b64_hashed_secret = base64.b64encode(h_secret)
		body_string = 'Location=%s&PublicKey=%s&UTCTimeStamp=%s&Version=1.0' % ('US1', key, urllib.quote(dt))
		clear = key + dt + body_string + b64_hashed_secret
		b64_clear = base64.b64encode(unicode(clear, 'utf-8'))

		h_signature = hmac.new(unicode(secret, 'utf-8'), unicode(clear, 'utf-8'), digestmod=hashlib.sha256).digest()
		b64_h_sig = base64.b64encode(h_hignature)
		double_enc_sig = base64.b64encode(unicode(b64_h_sig, 'utf-8'))
		b64_key = base64.b64encode(unicode(key, 'utf-8'))
		auth = base64.b64encode('%s:%s:%s' % (b64_key, double_enc_sig, b64_clear))
		return {'Authorization': 'KeyPair ' + auth, 
			'X-Public-Key': key, 
			'X-Timestamp': iso8601_timestamp,
			'URIPath' : resource_path,
			'Accept': 'application/json'}
	else:
		iso8601_timestamp = datetime.datetime.utcnow().isoformat() + "Z"
		clear = urllib.parse.quote('|'.join([key, resource_path, iso8601_timestamp, base64.b64encode(str.encode(body)).decode('utf-8') if body else "" ]))
		clear = re.sub(r'(%[A-F0-9]{2})', lambda x: x.group(0).lower(), clear)
		signature = base64.b64encode(hmac.new(str.encode(secret),str.encode(clear), digestmod=hashlib.sha256).digest())
		return {'Authorization': 'KeyPair' + base64.b64encode(signature).decode('utf-8'), 'X-Public-Key': key, 'X-Timestamp': iso8601_timestamp, 'URIPath' : resource_path}

def signed_common(uri, key, secret, reqfn, body='', verify_cert=True, auth_method='KeyPair'):
	bjson=''
	extraarg = {}
	if body != '':
		bjson = json.dumps(body)
		extraarg['json'] = body
		headers = make_auth_headers(key, secret, urlparse(uri).path, bjson, auth_method)
		headers['ACCEPT'] = 'application/json'
		res = reqfn(uri, headers=headers, verify=verify_cert,**extraarg)
		res.raise_for_status()
		return res.content

def signed_get(uri, key, secret, verify_cert=True, auth_method='KeyPair'):
	headers = make_auth_headers(key, secret, urlparse(uri).path, "", auth_method)
	headers['ACCEPT'] = 'application/json'
	res = requests.get(uri, headers=headers, verify=verify_cert)
	return res.content

xstream_api_public_key = '36354ecf-d047-d500-5a8a-48b6a93fed8f3e53174a-286e-e8bf-cea4-b7f0e99c7fb4'
xstream_api_private_key = "55dadb56-35ab-75ce-1a44-7f76e86e45c01e85d2b5-cb23-c877-af84-aa7302870964"
xstream_request_uri = 'https://mc-cloud.samsungsds.com/api/v1.3/PerformanceMetric'
verify_https_cert = False


req_body = {'TenantID' : "7822f6d6-23bb-422e-b103-899f1232831b",
	'MetricType':1,
	'Id': "127a3203-a6ee-d670-710f-f983543c6878"}


#r_type = requests.post
#post_response = signed_common(xstream_request_uri, xstream_api_public_key, xstream_api_private_key, r_type, req_body, verify_https_cert)
#print(post_response)


#get_response = signed_get(xstream_request_uri, xstream_api_public_key, xstream_api_private_key, verify_https_cert)
#print(get_response)


r_type = requests.get
get_response = signed_common(xstream_request_uri, xstream_api_public_key, xstream_api_private_key, r_type, req_body, verify_https_cert)
print(get_response)
