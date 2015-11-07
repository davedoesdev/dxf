# txf - have set up repo by hand.
# but when set-alias, had to > repository/targets
# and then add the targets again (what do about delete? just empty array and add dir again?)
# how trust root key in tuf?
# we need to add integration with tuf client so it can pull and then check the file hashes against targets.json etc

import os
import urlparse

import tuf
import tuf.download
import tuf.util

import dxf

def auth(dxf_obj, response):
    username = os.environ.get('DXF_USERNAME')
    password = os.environ.get('DXF_PASSWORD')
    if username and password:
        dxf_obj.auth_by_password(username, password, response=response)

def _download_file(url, required_length, STRICT_REQUIRED_LENGTH=True):
    ourl = urlparse.urlparse(url)
    repo, alias = ourl.path.split('//')
    dxf_obj = dxf.DXF(ourl.netloc, repo, auth)
    alias = dxf_obj.get_alias(alias)[0]
    temp_file = tuf.util.TempFile()
    try:
        for chunk in dxf_obj.pull_blob(alias):
            # need to check if length exceeded
            temp_file.write(chunk)
    except:
        temp_file.close_temp_file()
        raise
    # need to check enough data received
    return temp_file

tuf.download._download_file = _download_file


import tuf.client.updater

tuf.conf.repository_directory = 'tuf2'

repository_mirrors = {
    'mirror1': {
        # repo host is url host, repo is path except final part,
        # alias is the final part of the path
        'url_prefix': 'https://registry-1.docker.io/davedoesdev/rumptest',
        'metadata_path': '',
        'targets_path': '',
        'confined_target_dirs': ['']
    }
}

updater = tuf.client.updater.Updater('updater', repository_mirrors)

updater.refresh()

