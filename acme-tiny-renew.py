#!/usr/bin/env python3

#   MIT License
#
#   Copyright (c) 2019 Paul Elliott
#
#   Permission is hereby granted, free of charge, to any person obtaining a copy
#   of this software and associated documentation files (the "Software"), to deal
#   in the Software without restriction, including without limitation the rights
#   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#   copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in all
#   copies or substantial portions of the Software.
#
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#   SOFTWARE.

# A python script to wrap acme-tiny-renew (currently) in order to automate certificate
# renewal. Configuration is via standard ini file, and script is designed to be run
# via regular cron job (notifications can be done via email)

import os
import argparse
import configparser
import socket
import sys
from subprocess import Popen, PIPE
from datetime import datetime
import shlex
from enum import Enum
import requests
from traceback import format_exc
from tempfile import mkstemp

from LoggerManager.loggermanager import Logger_Manager, Loglevel
from exceptions import *

def check_elements(element_list, required_element_list, logger_manager, section_name):

    """ Check if a required list of elements are all in the config file """

    for element in required_element_list:
        if element not in element_list:
            raise ConfigError(section_name, "Essential element {} not found".format(element))
            return False

    return True

def do_shell_exec(exec_string, expected_result = 0):

    """ Execute the given string in a shell, try to ascertain success """

    shell_process = Popen(shlex.split(exec_string), stdin=PIPE, stdout=PIPE, stderr=PIPE)

    (shell_stdout, shell_stderr) = shell_process.communicate()

    if shell_process.returncode != expected_result:
        return False, shell_stdout.decode("utf-8"), shell_stderr.decode("utf-8")

    else:
        return True, shell_stdout.decode("utf-8"), shell_stderr.decode("utf-8")

def setup_logging(logger_manager, config_section, config_section_name):

    """ Setup logging dependant on the contents of the config file """

    essential_mail_elements = ["mail_to", "mail_from", "mail_server"]
    mail_elements = essential_mail_elements.copy()
    mail_elements.extend(["mail_server_port", "mail_subject"])

    if 'logfile' in config_section:
        logger_manager.setup_logfile(config_section.get("logfile"),
                                  config_section.get("num_rotated_logs", 5))

    mail_found = False

    # if one of the mail elements is in the config, make sure all the required ones are.
    for element in mail_elements:
        if element in config_section:
            mail_found = True
            break

    if mail_found == True:
        if check_elements(config_section, essential_mail_elements, logger_manager,
                          config_section_name):
            server = config_section.get("mail_server", "127.0.0.1")
            subject = config_section.get("mail_subject",
                                       "acme-tiny-renew on {}".format(socket.gethostname()))

            logger_manager.setup_mail(server, config_section.get("mail_from"),
                                  config_section.get("mail_to"), subject)

            return True
        else:
            return False
    else:
        return True

def install_certs(install_dir, cert_file_name, domain_cert, intermediate_cert, root_cert):

    """ Install certs (stored as ascii in arguments) to given directory, as variants of the
        base cert name given. """

    cert_filename_base, cert_filename_extension = os.path.splitext(cert_file_name)

    with open(os.path.join(install_dir, cert_file_name), "w") as out_file:
        out_file.write(domain_cert)

    with open(os.path.join(install_dir, "{}_chained{}".format(cert_filename_base,
                                                              cert_filename_extension)), "w") as out_file:
        out_file.write(domain_cert)
        out_file.write("\n\n")
        out_file.write(intermediate_cert)

    with open(os.path.join(install_dir, "{}_full{}".format(cert_filename_base,
                                                           cert_filename_extension)), "w") as out_file:
        out_file.write(domain_cert)
        out_file.write("\n\n")
        out_file.write(intermediate_cert)
        out_file.write("\n\n")
        out_file.write(root_cert)


def do_renew(logger_manager, renew_config, renew_config_name, renew_args):

    """ Do the actual renewal. Arguments are the config (and its name) and whether or not to force the
        renewal, or do a dry run """

    essential_elements = ["domain_name", "domain_csr", "account_key", "challenge_dir", "domain_cert"]

    if not check_elements(renew_config, essential_elements, logger_manager, renew_config_name):
        return False


    domain_cert_name = renew_config.get("domain_cert")

    # We do not want to overwrite the real cert with a staging version.
    if renew_args.staging:
        domain_cert_name = "staging_" + domain_cert_name

    # Check if this cert exists, and if it does, does it need renewal?
    if os.path.isfile(domain_cert_name):

        if not renew_args.force:
            # default to requires renewal within 7 days of time left.
            try:
                renew_min_timeleft = int(renew_config.get("renew_min_timeleft"), 7)

            except ValueError:
                raise ConfigError(renew_config_name, "renew_min_timeleft is not a number")


            # time left is measured in days, we need in seconds.
            exec_success, checkend_output, checkend_error = do_shell_exec("openssl x509 -in {} -checkend {}".format(domain_cert_name,
                                                                renew_min_timeleft * 24 * 60 * 60))

            if exec_success:
                # Don't actually need to renew this one
                logger_manager.log(Loglevel.INFO,
                                   "Cert exists, but does not require renewal within {} days".format(renew_min_timeleft))
                return False
            else:
                logger_manager.log(Loglevel.INFO,
                                   "Cert exists, but requires renewal (within {} days), attempting renewal...".format(renew_min_timeleft))
        else:
            logger_manager.log(Loglevel.INFO, "Cert exists, but --force has been used, attempting renewal...")

    else:
        logger_manager.log(Loglevel.INFO, "Cert does not exist, attempting renewal...")

    # Handle various options to specify the acme-tiny script.
    acme_tiny_dir = renew_config.get("acme_tiny_dir", "")

    if acme_tiny_dir == "":
        acme_tiny_command = renew_config.get("acme_tiny_command", "acme-tiny")
    else:
        acme_tiny_command = "{}/acme_tiny.py".format(acme_tiny_dir.rstrip().rstrip("/"))

    challenge_dir = renew_config.get("challenge_dir", "")

    if not os.path.isdir(challenge_dir):
        raise ConfigError(renew_config_name, "Challenge dir {} does not exist or is not directory".format(challenge_dir))

    if renew_args.dry_run:
        logger_manager.log(Loglevel.INFO, "Not actually renewing cert, dry run only.")
        return

    renew_command = "{} --account-key {} --csr {} --acme-dir {}".format(acme_tiny_command,
                                                                    renew_config.get("account_key"),
                                                                    renew_config.get("domain_csr"),
                                                                    challenge_dir)

    if renew_args.staging:
        renew_command = renew_command + "--directory-url https://acme-staging-v02.api.letsencrypt.org/directory"

    exec_success, domain_cert, exec_error = do_shell_exec(renew_command)

    if not exec_success:
        raise RenewError(renew_config_name, "Failed to renew cert {}".format(exec_error))

    logger_manager.log(Loglevel.INFO, "Cert renewed and fetched.")
    # Write this to a temp file, as we need to be able to work on it
    temp_file_handle, temp_file_name = mkstemp()

    with os.fdopen(temp_file_handle, "w") as temp_file:
        temp_file.write(domain_cert)

    # Figure out our issuer in order to download download trust chain.
    exec_success, cert_issuer, exec_error = do_shell_exec("openssl x509 -in {} -issuer -noout".format(temp_file_name))

    os.unlink(temp_file_name)

    if not exec_success:
        raise RenewError(renew_config_name, "Failed to get issuer for cert : {}".format(exec_error))

    if "Let's Encrypt" in cert_issuer:

        if renew_args.staging:
            root_cert_url = "https://letsencrypt.org/certs/isrgrootx1.pem"
        else:
            root_cert_url = "https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x1.pem"

        # All X'es are now retired
        if "X1" in cert_issuer and not renew_args.staging:
            intermediate_cert_url = "https://letsencrypt.org/certs/lets-encrypt-x1-cross-signed.pem"

        elif "X2" in cert_issuer and not renew_args.staging:
            intermediate_cert_url = "https://letsencrypt.org/certs/lets-encrypt-x2-cross-signed.pem"

        elif "X3" in cert_issuer and not renew_args.staging:
            intermediate_cert_url = "https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem"

        elif "X4" in cert_issuer and not renew_args.staging:
            intermediate_cert_url = "https://letsencrypt.org/certs/lets-encrypt-x4-cross-signed.pem"

        # Active
        elif "R3" in cert_issuer:
            if renew_args.staging:
                intermediate_cert_url = "https://letsencrypt.org/certs/staging/letsencrypt-stg-int-r3.pem"
            else:
                intermediate_cert_url = "https://letsencrypt.org/certs/lets-encrypt-r3-cross-signed.pem"

        # Disaster Backup
        elif "R4" in cert_issuer and not renew_args.staging:
            intermediate_cert_url = "https://letsencrypt.org/certs/lets-encrypt-r4-cross-signed.pem"

        # Coming Soon...
        elif "E1" in cert_issuer and not renew_args.staging:
            root_cert_url = "https://letsencrypt.org/certs/isrg-root-x2-cross-signed.pem"
            intermediate_cert_url = "https://letsencrypt.org/certs/lets-encrypt-e1.pem"

        # Disaster Backup
        elif "E2" in cert_issuer and not renew_args.staging:
            root_cert_url = "https://letsencrypt.org/certs/isrg-root-x2-cross-signed.pem"
            intermediate_cert_url = "https://letsencrypt.org/certs/lets-encrypt-e2.pem"

        # Script needs updating?
        else:
            raise RenewError(renew_config_name,
                             "Unknown Certificate Issuer {}".format(cert_issuer))

    else:
        # unsupported issuer (todo, add more here)
        raise RenewError(renew_config_name, "Unknown Certificate Issuer {}".format(cert_issuer))

    root_cert_request = requests.get(root_cert_url);

    if not root_cert_request.ok:
        raise RenewError(renew_config_name, "Failed to download root cert from {}".format(root_cert_url))

    logger_manager.log(Loglevel.INFO, "Downloaded root cert from {}".format(root_cert_url))
    root_cert = root_cert_request.text

    intermediate_cert_request = requests.get(intermediate_cert_url)

    if not intermediate_cert_request.ok:
        raise RenewError(renew_config_name,
                         "Failed to download intermediate cert from {}".format(intermediate_cert_url))

    logger_manager.log(Loglevel.INFO, "Downloaded intermediate cert from {}".format(intermediate_cert_url))
    intermediate_cert = intermediate_cert_request.text

    # install.
    domain_cert_dir, domain_cert_file = os.path.split(domain_cert_name)

    # first, back from whence it came.
    install_certs(domain_cert_dir, domain_cert_file, domain_cert, intermediate_cert, root_cert)

    # then to any install directories.
    if "install_dir" in renew_config:

        install_dir_array = renew_config.get("install_dir").split(',')

        for install_dir in install_dir_array:

            install_dir = install_dir.strip()

            if not os.path.exists(install_dir):
                logger_manager.log(Loglevel.INFO,
                                    "In section {}: Install dir {} does not exist, creating".format(renew_config_name,
                                                                                                   install_dir))
                os.mkdir(install_dir)

            elif not os.path.isdir(install_dir):
                raise ConfigError(renew_config_name, "Install directory {} isn't a directory".format(install_dir))

            install_certs(install_dir, domain_cert_file, domain_cert, intermediate_cert, root_cert)

            logger_manager.log(Loglevel.INFO, "Installed certs to {}".format(install_dir))

    # Can use post sync as hook to restart servers (if setup correctly)
    # Yes, this is dangerous, use with care, do not run script as root.
    if "post_sync" in renew_config:
        exec_success, checkend_output, exec_error = do_shell_exec(renew_config.get("post_sync"))


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='acme-tiny-renew')
    parser.add_argument('-c', '--config', help='Input config file',
                        type = argparse.FileType('r'), required = True)
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Log to standard out')

    options_group = parser.add_mutually_exclusive_group()
    options_group.add_argument('-f', '--force', action='store_true',
                               help='Force certificate renewal even if not required')
    options_group.add_argument('-d', '--dry_run', action='store_true',
                               help='Do not actually renew certificate, just do a dry run')
    options_group.add_argument('-s', '--staging', action='store_true',
                           help='Use lets encrypt staging environment (test setup)')
    args = parser.parse_args()

    if os.geteuid() == 0:
        exit("Running this script as root is not recommended, use sudo priviledges instead.")

    config = configparser.ConfigParser()
    config.read_file(args.config)

    logger_manager = Logger_Manager()

    for section_name in config.sections():

        renew_config = config[section_name]

        try:
            setup_logging(logger_manager, renew_config, section_name)
            do_renew(logger_manager, renew_config, section_name, args)

        except ConfigError as e:
            logger_manager.log(Loglevel.ERROR, "In Section {} : {}".format(e.GetSection(),
                                                                          e.GetMessage()))

        except RenewError as e:
            logger_manager.log(Loglevel.ERROR, e.GetMessage())


        except:
            logger_manager.log(Loglevel.ERROR, format_exc())

        finally:
            logger_manager.log(Loglevel.INFO, "### Script done.")


    logger_manager.send_mail()

