import os
import sys
import logging
import tempfile
import shutil
import tarfile
import json
import click
import time
import fetch
import sys

import requests
from requests.auth import HTTPBasicAuth



class Clair:
    def __init__(self, clair_service_uri, docker_host_uri, docker_image_uri, docker_image_tag, docker_reg_user, docker_reg_pw, vuln_severity_fail,log_server_uri):

        self.clair_service_uri = clair_service_uri
        self.docker_host_uri = docker_host_uri 
        self.docker_image_uri = docker_image_uri
        self.docker_image_tag = docker_image_tag
        self.docker_reg_user = docker_reg_user
        self.docker_reg_pw = docker_reg_pw
        self.vuln_severity_fail = vuln_severity_fail.replace(" ","").lower().split(",")  #Split potentially multiple sev fail values into a list

        self.time_stamp = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time()))

        logging.basicConfig(level=logging.WARNING,
                    format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                    datefmt='%m-%d %H:%M',
                    )

        self.log = logging.getLogger(__name__)

        self.docker_reg_token = fetch.check_auth(self.docker_host_uri + '/v2/' + self.docker_image_uri + '/manifests/' + self.docker_image_tag,self.docker_reg_user, self.docker_reg_pw)

        if docker_image_tag:
            self.docker_image_tag = docker_image_tag
        else:
            self.docker_image_tag = "latest"


        '''
        Cfg is a dict:

            cfg = {
                'clair.host': 'http://localhost:6060',
                'docker.connect': 'tcp://127.0.0.1:2375' or None for socks.

                }
        '''
        '''
        if self.docker_host_uri:
            self.docker_cli = Client(base_url=self.docker_host_uri, timeout=1800)
        else:
            self.docker_cli = Client(timeout=1800)
        '''

    def run(self):

        
        SYS_EXIT_FAIL = False #By default we're hoping that there are no vulnerabilities that match the list in self.vuln_severity_fail

        layers = self.analyse(self.docker_image_uri,self.docker_reg_token)

        layer_ids = []

        for layer in layers:
            layer_ids.append(layer['id'])

        time.sleep(5) #Give CLair some time to process the layers

        vulnerabilities = self.get_layers_vulnerabilities(layer_ids)
        
        self.log.debug(str(vulnerabilities) + '\n\n')

        for layer in vulnerabilities:           
            self.log.warn('Namespace: ' + layer.get('Layer',{}).get('NameSpaceNames','null'))
            self.log.warn('Name: ' + layer.get('Layer',{}).get('Name','null'))
                
            for feature in layer.get('Layer',{}).get('Features',{}):
                self.log.debug('\n\nFeature: ' + str(feature))
                self.log.warn('VersionFormat: ' + feature.get('VersionFormat','null'))
                self.log.warn('NamespaceName: ' + feature.get('NamespaceName','null'))
                self.log.warn('Version: ' + feature.get('Version','null'))
                self.log.warn('Name: ' + feature.get('Name','null'))
                self.log.warn('AddedBy: ' + feature.get('AddedBy','null'))
                for vulnerability in feature.get('Vulnerabilities',{}):
                    self.log.warn('\n\n>>>>Vulnerability CVE ID: '+ vulnerability.get('Name','null'))
                    self.log.warn('>>>>Vulnerability Description: '+ vulnerability.get('Description','null'))

                    self.log.warn('------Vulnerability Severity: '+ vulnerability.get('Severity','null'))
                    self.log.warn('------Vulnerability NamespaceName: '+ vulnerability.get('NamespaceName','null'))
                    self.log.warn('------Vulnerability Link: '+ vulnerability.get('Link','null'))
                    
                    self.log.warn('------Vulnerability Metadata Score: '+ str(vulnerability.get('Metadata',{}).get('NVD',{}).get('CVSSv2',{}).get('Score','null')))
                    self.log.warn('------Vulnerability Metadata Vectors: '+ vulnerability.get('Metadata',{}).get('NVD',{}).get('CVSSv2',{}).get('Vectors','null'))

                    if SYS_EXIT_FAIL == False:
                        if vulnerability.get('Severity','null').lower() in self.vuln_severity_fail:
                            SYS_EXIT_FAIL = True

        if SYS_EXIT_FAIL == True:  #One of the vulns found has a severity that exists in the --vuln-severity-fail argument values passed at the cmd line
            try:
                raise Exception
            except:
                self.log.warn("\n\nReturning non-zero sys.exit code: --vuln-severity-fail condition matched.")


    def analyse_layer(self, layer, token):
        '''
        POST http://localhost:6060/v1/layers HTTP/1.1

            {
              "Layer": {
                "Name": "523ef1d23f222195488575f52a39c729c76a8c5630c9a194139cb246fb212da6",
                "Path": "/mnt/layers/523ef1d23f222195488575f52a39c729c76a8c5630c9a194139cb246fb212da6/layer.tar",
                "ParentName": "140f9bdfeb9784cf8730e9dab5dd12fbd704151cf555ac8cae650451794e5ac2",
                "Format": "Docker"
              }
            }
        '''
        layer_vulns = dict()
        clair_layer = {
            'Layer': {
                'Name': layer['id'],
                'Path': layer['path'],
                'ParentName': layer['parent'],
                'Headers' : { 'Authorization': 'Bearer ' + token },
                'Format': 'Docker'
            }
        }
        
        self.log.debug(json.dumps(clair_layer))

        r = requests.post(self.clair_service_uri + '/v1/layers', data = json.dumps(clair_layer))
        
        if r.status_code != 201:
            self.log.debug('\n\nClair API call status code: ' + str(r.status_code))
            #self.log.debug('Www-Authenticate: ' + r.headers['WWW-Authenticate'])
            self.log.debug('Clair Error message: ' + r.text)
            logging.error(layer['image'] + ':Failed to analyse layer ' + layer['id'])
        else:
            self.log.debug('\n\nClair Response: ' + r.text)

        time.sleep(5)

    def analyse(self, image, token):
        layers = []
        manifest_json = str()
        manifest_filename = "manifest.json"
        parent_layer = str()
        layer_new_id = str()

        #(image_tar, tmp_path) = tempfile.mkstemp(suffix="-docker_image_ospkg_scan")
        self.log.debug('Fetching manifest...')

        #Returns a requests response object
        #manifest = fetch.manifest('https://registry-1.docker.io','library/nginx','latest')
        manifest = fetch.manifest(self.docker_host_uri,self.docker_image_uri,self.docker_image_tag, self.docker_reg_user,self.docker_reg_pw)
        self.log.debug(manifest)
        logging.debug(str(manifest))

        for layer in manifest['layers']:
            self.log.debug('\n\n' + str(layer))
            

            layers.append({ 'id': '_'.join(self.docker_image_uri.split('/')) + ':' + self.docker_image_tag + '_' +  layer['digest'],
                            'path': self.docker_host_uri + '/v2/' + self.docker_image_uri + '/blobs/' + layer['digest'],
                            'parent': parent_layer,
                            'image': image
            })
            parent_layer = layer['digest']

        self.log.debug('\n\nStarting to send layers to Clair.\n')

        for layer in layers:
            self.analyse_layer(layer,token)

        #os.remove(tmp_path)
        #shutil.rmtree(tmp_dir)
        return layers


    def get_layers_vulnerabilities(self, layer_ids):
        vulnerabilities = []
        for layer_id in layer_ids:
            layer_vulnerabilities = self.get_layer_vulnerabilities(layer_id)
            if layer_vulnerabilities is not None:
                vulnerabilities.append(layer_vulnerabilities)
        return vulnerabilities

    def get_layer_vulnerabilities(self, layer_id):
        '''
        GET http://localhost:6060/v1/layers/17675ec01494d651e1ccf81dc9cf63959ebfeed4f978fddb1666b6ead008ed52?features&vulnerabilities
        '''
        r = requests.get(self.clair_service_uri +'/v1/layers/'+layer_id+'?features&vulnerabilities')
        if r.status_code != 200:
            self.log.debug('\n\nClaire fetching vulnerabilities')
            self.log.debug(r.status_code)
            self.log.debug(r.text)
            time.sleep(5)
            logging.error('Could not get info on layer '+layer_id)
            return None
        return r.json()


@click.command(help='Use --help to display usage.',short_help='Use --help to display usage.')
#@click.Context(,help_option_names=['','-h','--help'])
@click.option('--clair-service-uri', default='http://localhost:6060', help='URI for the Clair service. Defaults to: http://localhost:6060', required=True)
@click.option('--docker-reg-uri', default='https://registry-1.docker.io', help='URI for the Docker host. Defaults to: https://registry-1.docker.io', required=True)
@click.option('--docker-image-uri', help='URI for the Docker image to be scanned. Format: library/nginx.', required=True)
@click.option('--docker-image-tag', default='latest', help='Tag for the Docker image. Defaults to latest.')
@click.option('--docker-reg-user', default='',help='Username for private docker repository authentication.')
@click.option('--docker-reg-pw', default='', help='Password for private docker repository authentication.')
@click.option('--vuln-severity-fail', default='', show_default=True,
    help='Vulnerability severity levels which should trigger an failure exit code (e.g. to fail Jenkins jobs). Valid option values are All, Negligible, Low, Medium, High, and Critical. Multiple arguments are allowed when used as "--vuln-severity-fail high,medium"')
@click.option('--log-server-uri', default='', help='HTTP or HTTPS URI for the log server. Logs are delivered as individual JSON objects (per vulnerability) separated by newlines.')

def main1(clair_service_uri, docker_reg_uri, docker_image_uri, docker_image_tag, docker_reg_user, docker_reg_pw, vuln_severity_fail, log_server_uri):

    if docker_reg_user != '':
        if docker_reg_pw == '':
            #sys.exit("Error: A non-empty password is required when a username is provided.")
            raise Exception("Error: A non-empty password is required when a username is provided.")

    Clair(
        clair_service_uri,
        docker_reg_uri,
        docker_image_uri,
        docker_image_tag,
        docker_reg_user,
        docker_reg_pw,
        vuln_severity_fail
        log_server_uri
        ).run()


if __name__ == '__main__':
    main1()

