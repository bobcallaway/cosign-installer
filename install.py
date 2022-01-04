#!/usr/bin/env python
#
# Copyright 2021 The Sigstore Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import hashlib
import logging
import os
import re
import subprocess
import stat
import urllib.request


def log_and_exit(msg: str):
    """logs a message at error level and causes the program to exit
       with a error code of 1
    """

    logger.error(msg)
    exit(1)


def chmod_plus_x(filename: str):
    """ gives executable permissions to the specified file
        equivalent to 'chmod +x filename'
    """
    st = os.stat(filename)
    os.chmod(filename, st.st_mode | stat.S_IEXEC)


def download_and_hash(url: str, path: str, sha_to_verify=None) -> str:
    """ download a file from given url and writes to path
        computes SHA256 sum of downloaded file, optionally verifying it against
        sha_to_verify

        returns the sha256 digest as a hexadecimal string
    """
    logger.debug(f"downloading {url}")
    try:
        with urllib.request.urlopen(url) as resp, open(path, 'wb') as out_file:
            sha256=hashlib.sha256()
            for block in iter(lambda: resp.read(65536), b''):
                sha256.update(block)
                out_file.write(block)
            out_file.close()
            if sha_to_verify and sha256.hexdigest() != sha_to_verify.lower():
                raise "Unable to validate download against expected digest"
            return sha256.hexdigest()
    except Exception as e:
        log_and_exit(e)


class CustomFormatter(logging.Formatter):
    """Logging colored formatter"""

    grey = '\x1b[38;21m'
    blue = '\x1b[38;5;39m'
    yellow = '\x1b[38;5;226m'
    red = '\x1b[38;5;196m'
    bold_red = '\x1b[31;1m'
    reset = '\x1b[0m'

    def __init__(self, fmt: str):
        super().__init__()
        self.fmt = fmt
        self.FORMATS = {
            logging.DEBUG: self.grey + self.fmt + self.reset,
            logging.INFO: self.blue + self.fmt + self.reset,
            logging.WARNING: self.yellow + self.fmt + self.reset,
            logging.ERROR: self.red + self.fmt + self.reset,
            logging.CRITICAL: self.bold_red + self.fmt + self.reset
        }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


# BEGIN MAIN PROGRAM FLOW
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Define format for logs
fmt = '%(asctime)s | %(levelname)8s | %(message)s'

# Create stdout handler for logging to the console (logs all five levels)
stdout_handler = logging.StreamHandler()
stdout_handler.setLevel(logging.DEBUG)
stdout_handler.setFormatter(CustomFormatter(fmt))
logger.addHandler(stdout_handler)

# source bootstrap_version.txt
logger.info('reading in bootstrap information...')
from bootstrap_version import *

# check for bootstrap version
if not bootstrap_version:
    log_and_exit("bootstrap version could not be determined, exiting")

logger.info(f"bootstrap version '{ bootstrap_version }' of cosign requested")

# check for installation directory value
install_dir=os.getenv("INSTALL_DIR")
if not install_dir:
    log_and_exit("installation path could not be determined, exiting")

# ensure the cosign release version requested is well-formed
cosign_release=os.getenv('COSIGN_RELEASE', "")
if not re.match(r"v([0-9]+\.){0,2}(\*|[0-9]+)$", cosign_release):
    log_and_exit(f"invalid cosign release '{ cosign_release }' requested")
elif cosign_release != bootstrap_version:
    logger.info(f"requesting custom cosign release '{ cosign_release }'")

# create the installation directory if it doesn't exist already
try:
    os.mkdir(install_dir)
    logger.debug(f"created installation directory at { install_dir }")
except FileExistsError:
    logger.debug(f"installation directory '{ install_dir }' already exists")

# determine the file names based on OS and processor architecture
OS=os.getenv('RUNNER_OS')
arch=os.getenv('RUNNER_ARCH')
if OS == "Linux":
    if arch == "X64":
        bootstrap_filename='cosign-linux-amd64'
        bootstrap_sha=bootstrap_linux_amd64_sha
        desired_cosign_filename='cosign-linux-amd64'
        # v0.6.0 had different filename structures from all other releases
        if os.getenv('COSIGN_RELEASE') == 'v0.6.0':
            desired_cosign_filename='cosign_linux_amd64'
            desired_cosign_v060_signature='cosign_linux_amd64_0.6.0_linux_amd64.sig'

    elif arch == "ARM":
        bootstrap_filename='cosign-linux-arm'
        bootstrap_sha=bootstrap_linux_arm_sha
        desired_cosign_filename='cosign-linux-arm'
        # v0.6.0 had different filename structures from all other releases
        if os.getenv('COSIGN_RELEASE') == 'v0.6.0':
            desired_cosign_filename='cosign_linux_arm'
            desired_cosign_v060_signature='cosign_linux_arm_0.6.0_linux_arm.sig'

    elif arch == "ARM64":
        bootstrap_filename='cosign-linux-arm64'
        bootstrap_sha=bootstrap_linux_arm64_sha
        desired_cosign_filename='cosign-linux-arm64'
        # v0.6.0 had different filename structures from all other releases
        if os.getenv('COSIGN_RELEASE') == 'v0.6.0':
            desired_cosign_filename='cosign_linux_arm64'
            desired_cosign_v060_signature='cosign_linux_arm64_0.6.0_linux_arm64.sig'

    else:
        log_and_exit(f"unsupported architecture '{os.getenv('RUNNER_ARCH')}' detected")

elif OS == "macOS":
    if arch == "X64":
        bootstrap_filename='cosign-darwin-amd64'
        bootstrap_sha=bootstrap_darwin_amd64_sha
        desired_cosign_filename='cosign-darwin-amd64'
        # v0.6.0 had different filename structures from all other releases
        if os.getenv('COSIGN_RELEASE') == 'v0.6.0':
            desired_cosign_filename='cosign_darwin_amd64'
            desired_cosign_v060_signature='cosign_darwin_amd64_0.6.0_darwin_amd64.sig'

    elif arch == "ARM64":
        bootstrap_filename='cosign-darwin-arm64'
        bootstrap_sha=bootstrap_darwin_arm64_sha
        desired_cosign_filename='cosign-darwin-arm64'
        # v0.6.0 had different filename structures from all other releases
        if os.getenv('COSIGN_RELEASE') == 'v0.6.0':
            desired_cosign_filename='cosign_darwin_arm64'
            desired_cosign_v060_signature='cosign_darwin_arm64_0.6.0_darwin_arm64.sig'

    else:
        log_and_exit(f"unsupported architecture '{os.getenv('RUNNER_ARCH')}' detected")
elif OS == "Windows":
    # TODO: implement me
    pass
else:
    log_and_exit(f"Runner OS detected '{OS}' is not supported!")

# download bootstrap version of cosign, also verify SHA against externally set values
bootstrap_file_with_path=f"{os.getenv('INSTALL_DIR')}/cosign"
bootstrap_url=f"https://storage.googleapis.com/cosign-releases/{ bootstrap_version }/{ bootstrap_filename }"
logger.info(f"Downloading bootstrap version '{ bootstrap_version }' of cosign to verify version to be installed")
download_and_hash(bootstrap_url, bootstrap_file_with_path, sha_to_verify=bootstrap_sha)
chmod_plus_x(bootstrap_file_with_path)
logger.info(f"wrote and verified bootstrap cosign binary to { bootstrap_file_with_path }")

# if the user requested the same version as the bootstrap one, exit here successfully
if cosign_release == bootstrap_version:
    logger.info("bootstrap version successfully verified and matches requested version so nothing else to do")
    exit()

# Download specific version of cosign that was requested
custom_cosign_url=f"https://storage.googleapis.com/cosign-releases/{ cosign_release }/{ desired_cosign_filename }"
logger.info(f"Downloading requested cosign version '{ cosign_release }'")
desired_cosign_filename_with_path=f"{ install_dir }/{ desired_cosign_filename }"
sha = download_and_hash(custom_cosign_url, desired_cosign_filename_with_path)
if sha != bootstrap_sha:
    logger.info(f"Downloading detached signature for platform-specific '{ cosign_release }' release of cosign...")
    signature_path=f"{desired_cosign_filename_with_path}.sig"
    if cosign_release == 'v0.6.0':
        signature_url=f"https://github.com/sigstore/cosign/releases/download/{ cosign_release }/{ desired_cosign_v060_signature }"
    else:
        signature_url=f"https://github.com/sigstore/cosign/releases/download/{ cosign_release }/{ desired_cosign_filename }.sig"
    download_and_hash(signature_url, signature_path)

    # set url to fetch public key used to sign cosign release
    if cosign_release < "v0.6.0":
        release_public_key_url=f"https://raw.githubusercontent.com/sigstore/cosign/{ cosign_release }/.github/workflows/cosign.pub"
    else:
        release_public_key_url=f"https://raw.githubusercontent.com/sigstore/cosign/{ cosign_release }/release/release-cosign.pub"

    logger.info("Using bootstrap cosign to verify signature of desired cosign version")

    # this will verify the digital signature against the specified public key
    subprocess.run([bootstrap_file_with_path, "verify-blob", "--key", release_public_key_url, "--signature", signature_path, desired_cosign_filename_with_path])

    # this deletes the bootstrap version and moves the requested file into place
    os.remove(bootstrap_file_with_path)
    os.rename(desired_cosign_filename_with_path, bootstrap_file_with_path)
    chmod_plus_x(bootstrap_file_with_path)

logger.info("Installation complete!")
