import requests
import json
import re

def run():
	
	CLAIR_URI = 'http://172.20.38.244:6060/v1/layers'

	payload= dict()
	
	registry_reponse = requests.get('https://registry-1.docker.io/v2/library/nginx/blobs/sha256:ff3d52d8f55fb0b74ea0a24134f75efeff780c4e1f407073def2ae9c9b900868')

	print registry_reponse.status_code
	print registry_reponse.headers['content-type']
	print registry_reponse.headers['WWW-Authenticate']
	print registry_reponse.text

	#If the registry returns a 400 status code with a WWW-Authenticate header, we'll have to authenticate.
	#Parsing out the OAuth authentication information from the WWW-Authenticate header

	if registry_reponse.headers['WWW-Authenticate']:
		
		m = re.search('service="(.+?)",', registry_reponse.headers['WWW-Authenticate'])
		if m:
			TOKEN_SERVER_SERVICE = m.group(1)

		n = re.search('scope="(.+?)"', registry_reponse.headers['WWW-Authenticate'])
		if n:
			TOKEN_SERVER_SCOPE = n.group(1)

		o = re.search('realm="(.+?)"', registry_reponse.headers['WWW-Authenticate'])
		if o:
			TOKEN_SERVER_REALM = o.group(1)


	print "TOKEN_SERVER_REALM: " + TOKEN_SERVER_REALM
	print "TOKEN_SERVER_SERVICE: " + TOKEN_SERVER_SERVICE
	print "TOKEN_SERVER_SCOPE: " + TOKEN_SERVER_SCOPE

	TOKEN_SERVER_URL = TOKEN_SERVER_REALM + '?service=' + TOKEN_SERVER_SERVICE + '&scope=' + TOKEN_SERVER_SCOPE

	print TOKEN_SERVER_URL

	tokenserver_response = requests.get(TOKEN_SERVER_URL)

	print tokenserver_response.status_code
	print tokenserver_response.headers['content-type']
	#print tokenserver_response.headers['WWW-Authenticate']
	print tokenserver_response.json()


	token = json.loads(json.dumps(tokenserver_response.json()))['access_token']

	print '\n\nRegistry Authentication Token: ' + token
	

	"""
	print "\n\n<<< TESTING DOCKER LAYER DOWNLOAD >>>"
	headers = {'Authorization': 'Bearer ' + token}
	registry_reponse = requests.get('https://registry-1.docker.io/v2/library/nginx/blobs/sha256:ff3d52d8f55fb0b74ea0a24134f75efeff780c4e1f407073def2ae9c9b900868', headers=headers)

	print registry_reponse.status_code
	print registry_reponse.headers['content-type']
	print registry_reponse.headers['WWW-Authenticate']
	print registry_reponse.text

	"""

	print "\n\n<<< STARTING CLAIR API CALL >>>"

	payload['Layer'] = dict()
	payload['Layer']['Name'] = 'library/nginx'
	payload['Layer']['Path'] = 'https://registry-1.docker.io/v2/library/nginx/blobs/sha256:ff3d52d8f55fb0b74ea0a24134f75efeff780c4e1f407073def2ae9c9b900868'
	payload['Layer']['Headers'] = dict()
	payload['Layer']['Headers']['Authorization'] = 'Bearer ' + token
	payload['Layer']['Parentname'] = ''
	payload['Layer']['Format'] = 'Docker'

	data = json.dumps(payload)
	print "\n\nCLAIR CALL PAYLOAD:\n"
	print data 

	headers = {'content-type': 'application/json; charset=UTF-8', 'accept': 'application/json'}
	clair_response = requests.post(CLAIR_URI, data=data, headers=headers)

	print clair_response.status_code
	print clair_response.headers['content-type']

	print clair_response.text
	

	

if __name__ == '__main__':
    run()

