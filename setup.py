import io
import os
from setuptools import setup

def read(name):
    file_path = os.path.join(os.path.dirname(__file__), name)
    return io.open(file_path, encoding='utf8').read()

setup(
    name='python-dxf',
    version='10.0.0',
    description="Package for accessing a Docker v2 registry",
    long_description=read('README.rst'),
    keywords='docker registry',
    author='David Halls',
    author_email='dave@davedoesdev.com',
    url='https://github.com/davedoesdev/dxf',
    license='MIT',
    packages=['dxf'],
    package_data={"dxf": ["py.typed"]},
    entry_points={'console_scripts': ['dxf=dxf.main:main']},
    install_requires=['www-authenticate>=0.9.2',
                      'requests>=2.18.4',
                      'jwcrypto>=1.4.2',
                      'tqdm>=4.19.4'],
    python_requires='>=3.7'
)
