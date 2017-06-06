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

import requests
from requests.auth import HTTPBasicAuth

class Clair:
    def __init__(self, clair_service_uri, docker_host_uri, docker_image_uri, docker_image_tag, docker_reg_user, docker_reg_pw):

        self.clair_service_uri = clair_service_uri
        self.docker_host_uri = docker_host_uri 
        self.docker_image_uri = docker_image_uri
        self.docker_image_tag = docker_image_tag
        self.docker_reg_user = docker_reg_user
        self.docker_reg_pw = docker_reg_pw
        self.time_stamp = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time()))

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

        log = logging.getLogger(__name__)

        layers = self.analyse(self.docker_image_uri,self.docker_reg_token)

        layer_ids = []

        for layer in layers:
            layer_ids.append(layer['id'])

        time.sleep(15) #Give CLair some time to process the layers
        vulnerabilities = self.get_layers_vulnerabilities(layer_ids)

        log.warn(str(vulnerabilities))


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
        clair_layer = {
            'Layer': {
                'Name': layer['id'],
                'Path': layer['path'],
                'ParentName': layer['parent'],
                'Headers' : { 'Authorization': 'Bearer ' + token },
                'Format': 'Docker'
            }
        }
        
        print json.dumps(clair_layer)

        r = requests.post(self.clair_service_uri + '/v1/layers', data = json.dumps(clair_layer))

        
        
        if r.status_code != 201:
            print '\n\nClair API call status code: ' + str(r.status_code)
            #print 'Www-Authenticate: ' + r.headers['WWW-Authenticate']
            print 'Clair Error message: ' + r.text
            logging.error(layer['image'] + ':Failed to analyse layer ' + layer['id'])
        else:
            print '\n\nClair Response: ' + r.text

        time.sleep(5)

    def analyse(self, image, token):
        layers = []
        manifest_json = str()
        manifest_filename = "manifest.json"
        parent_layer = str()
        layer_new_id = str()

        #(image_tar, tmp_path) = tempfile.mkstemp(suffix="-docker_image_ospkg_scan")
        print 'Fetching manifest...'

        #Returns a requests response object
        #manifest = fetch.manifest('https://registry-1.docker.io','library/nginx','latest')
        manifest = fetch.manifest(self.docker_host_uri,self.docker_image_uri,self.docker_image_tag, self.docker_reg_user,self.docker_reg_pw)
        print manifest
        logging.debug(str(manifest))

        for layer in manifest['layers']:
            print '\n\n' + str(layer)
            

            layers.append({ 'id': '_'.join(self.docker_image_uri.split('/')) + ':' + self.docker_image_tag + '_' +  layer['digest'],
                            'path': self.docker_host_uri + '/v2/' + self.docker_image_uri + '/blobs/' + layer['digest'],
                            'parent': parent_layer,
                            'image': image
            })
            parent_layer = layer['digest']

        print '\n\nStarting to send layers to Clair.\n'

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
            print '\n\nClaire fetching vulnerabilities'
            print r.status_code
            print r.text
            time.sleep(5)
            logging.error('Could not get info on layer '+layer_id)
            return None
        return r.json()


@click.command()
@click.option('--clair-service-uri', help='URI for the Clair service. Format: http://localhost:6060', required=True)
@click.option('--docker-reg-uri', help='URI for the Docker host. Format: https://registry-1.docker.io', required=False)
@click.option('--docker-image-uri', help='URI for the Docker image to be scanned. Format: library/nginx ', required=True)
@click.option('--docker-image-tag', help='Tag for the Docker image')
@click.option('--docker-reg-user', help='Tag for the Docker image')
@click.option('--docker-reg-pw', help='Tag for the Docker image')

def main1(clair_service_uri, docker_reg_uri, docker_image_uri, docker_image_tag, docker_reg_user, docker_reg_pw):
    Clair(
        clair_service_uri,
        docker_reg_uri,
        docker_image_uri,
        docker_image_tag,
        docker_reg_user,
        docker_reg_pw
        ).run()


if __name__ == '__main__':
    main1()

