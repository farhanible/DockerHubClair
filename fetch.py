import requests
import json
import re
from requests.auth import HTTPBasicAuth

def manifest(registry_uri,docker_image,docker_tag,user,password):

	docker_image_manifest_uri = registry_uri + '/v2/' + docker_image + '/manifests/' + docker_tag

	token = check_auth(docker_image_manifest_uri,user,password)

	if type(token) == bool:
		if token:
			return get_file(docker_image_manifest_uri)
		else:
			return
	else:
		return get_file(docker_image_manifest_uri,token,user,password)


def check_auth(uri,user,password):

	headers = {'Accept': 'application/vnd.docker.distribution.manifest.v2+json'}
	manifest_response = requests.head(uri,headers=headers, auth=(user, password))

	print manifest_response.status_code
	print manifest_response.headers['content-type']
	print manifest_response.headers['WWW-Authenticate']
	print manifest_response.text

	if manifest_response.status_code/100 != 2 and manifest_response.headers['WWW-Authenticate']:
		print '\n\nReceived non 200 HTTP code. Attempting to get registry auth token.'

		if user != "":
			print '\n\nAttempting OAuth authentication: '
			return(get_registry_token_auth(manifest_response.headers['WWW-Authenticate'], user, password))
		else:
			return(get_registry_token(manifest_response.headers['WWW-Authenticate']))
	elif manifest_response.status_code/100 == 2:
		print '\n\nUnauthenticated registry.'
		return True
	else:
		print '\n\nNo WWW-Authenticate header returned. Cannot obtain registry auth token. Failed with HTTP status code: ' + manifest_response.status_code
		return False


def get_registry_token(www_auth):
	
	m = re.search('service="(.+?)",', www_auth)

	if m:
		TOKEN_SERVER_SERVICE = m.group(1)

	n = re.search('scope="(.+?)"', www_auth)
	if n:
		TOKEN_SERVER_SCOPE = n.group(1)

	o = re.search('realm="(.+?)"', www_auth)
	if o:
		TOKEN_SERVER_REALM = o.group(1)
	
	print "TOKEN_SERVER_REALM: " + TOKEN_SERVER_REALM
	print "TOKEN_SERVER_SERVICE: " + TOKEN_SERVER_SERVICE
	print "TOKEN_SERVER_SCOPE: " + TOKEN_SERVER_SCOPE

	TOKEN_SERVER_URL = TOKEN_SERVER_REALM + '?service=' + TOKEN_SERVER_SERVICE + '&scope=' + TOKEN_SERVER_SCOPE

	print "\n\nTOKEN_SERVER_URL: " + TOKEN_SERVER_URL
	
	#Publicly accessible images still require authentication tokens on OAuth authenticated registries.
	#But they do not require Basic authentication. The authorization server hands out tokens like candy.
	tokenserver_response = requests.get(TOKEN_SERVER_URL)

	print tokenserver_response.status_code
	print tokenserver_response.headers['content-type']
	#print tokenserver_response.headers['WWW-Authenticate']
	print tokenserver_response.json()


	token = json.loads(json.dumps(tokenserver_response.json()))['access_token']

	print '\n\nRegistry Authentication Token: ' + token

	return token

#OAuth authentication for private repositories
def get_registry_token_auth(www_auth, user, password):

	m = re.search('service="(.+?)",', www_auth)

	if m:
		TOKEN_SERVER_SERVICE = m.group(1)

	n = re.search('scope="(.+?)"', www_auth)
	if n:
		TOKEN_SERVER_SCOPE = n.group(1)

	o = re.search('realm="(.+?)"', www_auth)
	if o:
		TOKEN_SERVER_REALM = o.group(1)

	print "TOKEN_SERVER_REALM: " + TOKEN_SERVER_REALM
	print "TOKEN_SERVER_SERVICE: " + TOKEN_SERVER_SERVICE
	print "TOKEN_SERVER_SCOPE: " + TOKEN_SERVER_SCOPE
	print "User: " + user

	data = {"service": TOKEN_SERVER_SERVICE, "scope": TOKEN_SERVER_SCOPE, "account": user} #"username": user, "password": password, 
	headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"} 
	
	print "\n\nGET params: " + json.dumps(data)
	
	tokenserver_response = requests.get(TOKEN_SERVER_REALM, params=data, auth=(user,password), headers=headers) #auth=(user,password), headers=headers

	print tokenserver_response.url
	print tokenserver_response.status_code
	print tokenserver_response.headers['content-type']
	#print tokenserver_response.headers['WWW-Authenticate']
	print tokenserver_response.content

	token = json.loads(json.dumps(tokenserver_response.json()))['token']

	return token


def get_file(uri, token, user, password):

	headers = {'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.docker.distribution.manifest.v2+json'}
	#'Accept': 'application/vnd.docker.distribution.manifest.list.v2+json'

	registry_reponse = requests.get(uri, headers=headers) #, auth=(user, password)

	print registry_reponse.url
	print registry_reponse.status_code
	print registry_reponse.headers['content-type']
	print registry_reponse.text

	if registry_reponse.headers.get('WWW-Authenticate'):
		print registry_reponse.headers['WWW-Authenticate']

	return json.loads(json.dumps(registry_reponse.json()))


if __name__ == '__main__':
    run('https://registry-1.docker.io','library/nginx','latest')
