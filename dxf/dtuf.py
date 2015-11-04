
import urlparse

import tuf
import tuf.download
import tuf.util

def _download_file(url, required_length, STRICT_REQUIRED_LENGTH=True):
    repo, alias = urlparse.urlparse(url).path.split('//')
    # use dxf to download. make it into a proper module with exported functions,
    # will need to handle auth properly somehow. probably just raise exception
    # which can be recognised and caught.

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

