#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""https://github.com/rbeede/network-stability-monitor"""

# Python3 built-ins
import datetime
import dns.rdatatype
import dns.resolver
import itertools
import logging
from logging.handlers import RotatingFileHandler
import multiprocessing
import requests
import subprocess
import sys
import time

__author__ = "Rodney Beede"
__copyright__ = "© 2025 Rodney Beede"
__credits__ = []
__license__ = "AGPL 3, https://www.gnu.org/licenses/agpl-3.0.en.html"
__version__ = "2025.04.02"
__maintainer__ = "Rodney Beede"

logger = logging.getLogger(__name__)


class Config():
    MONITORING_INTERVAL = 1.0  # seconds

    TIMEOUT = 1  # seconds

    OUTAGE_THRESHOLD = 25 / 100  # percent

    # If any one of these pass then outage is considered over
    #   Best to pick remotes and nothing on local network
    # IP of DNS resolver to use
    # Easy A query to lookup that will not require recursive lookup
    DNS_PAIRS = [
        ('1.0.0.1', 'one.one.one.one'),  # Cloudflare
        ('8.8.4.4', 'dns.google'),
        ('208.67.222.123', 'familyshield.opendns.com'),
        ('149.112.112.112', 'dns.quad9.net'),
        ('94.140.14.141', 'unfiltered.adguard-dns.com'),
    ]

    # Used to verify if outage is real
    ICMP_TARGETS = [
        ('www.google.com', "Google"),
        ('www.amazon.com', 'Amazon'),
        ('www.microsoft.com', 'Microsoft'),
        ('192.168.1.1', 'Local Network Gateway'),
        ('100.64.1.1', 'ISP Node'),
        ('100.127.255.1', 'ISP Uplink Tier'),
    ]

    # Used to verify if outage is real
    WEB_TARGETS = [
        # Using http: (instead of https) on purpose for faster handshakes
        # These will be queried with HEAD
        'http://www.google.com/',
        'http://www.amazon.com/',
        'http://www.gvtc.com/',  # ISP
        'http://www.microsoft.com/',
        'http://www.rodneybeede.com/',  # best website ever
    ]


def main():
    setup_logging(sys.argv[1])

    config = Config()

    start_of_failure = None
    last_success = None

    for dns_pair in itertools.cycle(config.DNS_PAIRS):
        loop_start = time.time()

        logger.debug(f"Interval check using {dns_pair}")

        dns_client = dns.resolver.Resolver(configure=False)
        dns_client.nameservers=[dns_pair[0]]
        dns_client.timeout=config.TIMEOUT  # if using multiple resolver servers how long to wait on each one
        dns_client.lifetime=config.TIMEOUT  # how long to wait for the entire thing
        dns_client.cache=None  # default
        dns_client.retry_servfail=False  # default

        try:
            answer = dns_client.resolve(
                qname=dns_pair[1],
                rdtype=dns.rdatatype.A,
                tcp=False  # UDP
                )
        except (dns.resolver.LifetimeTimeout, dns.resolver.NoNameservers) as e:
            logger.debug(e)
            answer = None

        if not answer:
            logger.warning(f"Failed to resolve using {dns_pair}. Network may be down, kicking off deep check")

            if deep_check(config):
                if start_of_failure:  # already in downime
                    logger.debug('Already knew network down, network is still down')
                else:
                    logger.error('New outage detected')
                    start_of_failure = time.time()
            else:
                logger.debug('False alarm, deep check of network passed; no outage')
                # We won't consider this a last_success; so if there was a current outage we don't reset it
                # The next loop around needs to pass for that to occur
        else:  # Network is still up or came back up
            last_success = time.time()

            if start_of_failure:  # Just saw recovery from a failure
                outage_duration_seconds = last_success - start_of_failure

                logger.info('Saw recovery from network outage')
                logger.info('Duration of outage was ' + str(datetime.timedelta(seconds=outage_duration_seconds)))
            
            start_of_failure = None
            logger.debug(f"Network connection test passed with DNS pair {dns_pair} answering " + "\t".join(str(x) for x in answer))


        # It may have taken more than the desired monitoring interval to complete all the above
        # or it may have taken less time
        # Calculate if we need to wait at all so we do not go too fast
        time_taken = time.time() - loop_start
        logger.debug(f"It took {time_taken} seconds to complete the last interval check")
        if time_taken < config.MONITORING_INTERVAL:
            logger.debug('Finished early so sleeping')
            time_to_sleep_in_seconds = config.MONITORING_INTERVAL - time_taken
            time.sleep(time_to_sleep_in_seconds)


def setup_logging(log_filepath):
    handler = RotatingFileHandler(
        filename=log_filepath,
        maxBytes=20 * 1024 * 1024 * 1024,  # GiB
        backupCount=0,
        encoding='utf-8',
    )

    handler.setFormatter(
        logging.Formatter('%(asctime)s %(levelname)-8s %(message)s')
    )

    handler.setLevel(logging.DEBUG)

    logger.addHandler(handler)

    logger.setLevel(logging.DEBUG)


def deep_check(config):
    number_total_checks_made = len(config.ICMP_TARGETS) + len(config.WEB_TARGETS)
    number_failures = 0

    # Possible network outage so run all these checks to verify if network looks down for most things or only a few
    for target in config.ICMP_TARGETS:
        logger.debug(f"Pinging {target}")

        if not ping(target[0], config.TIMEOUT):
            logger.warning(f"Failed ICMP ping to {target}")
            number_failures += 1
        else:
            logger.debug(f"Successful ICMP ping to {target}")

    for target in config.WEB_TARGETS:
        logger.debug(f"Web query to {target}")

        if website_alive(target, config.TIMEOUT):
            logger.debug(f"Success web query to {target}")
        else:
            logger.warning(f"Failed web HEAD query to {target}")
            number_failures += 1

    logger.debug(f"Out of {number_total_checks_made} checks made there were {number_failures} failures")

    return number_failures > (number_total_checks_made * config.OUTAGE_THRESHOLD)  # if failures exceed percentage of total checks



def ping(target, timeout):
    # To avoid needing elevated privileges for Python we call the external ping binary instead
    # This is simpler for the install and usage of the program
    # Currently only supports POSIX ping command options (no Windows)
    try:
        completed_process = subprocess.run(
            ['ping', '-b', '-c', '1', '-n', '-p', 'ff', '-W', str(timeout), target],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout * 1.25,  # Needs to be slightly longer than timeout above for ping command itself
            )
    except subprocess.TimeoutExpired as e:
        # ping command could not complete (possible dns lookup delay of target) in time so return
        logger.debug(e)
        return False
    
    return completed_process.returncode == 0


def website_alive(url, timeout):
    # If all dns times out it can force retries of dns that take longer than desired timeout
    # So we have to use a Process inside to enforce request timeout
    queue = multiprocessing.SimpleQueue()
    process = multiprocessing.Process(
        args=(url,timeout,queue),
        name="TimedRequest",
        target=website_alive_helper
    )

    process.start()
    process.join(timeout)

    if process.is_alive():
        # It is still running in the background unsuccessfully
        process.terminate()
        process.join()

        logger.debug(f"Timeout of {timeout} reached for {url}")
        return False

    response = queue.get()
    logger.debug(f"website_alive: {response}")
    # In the event the connection was made but no response do a sanity check
    return response and response.headers


def website_alive_helper(url, timeout, queue):
    # Disable any retries
    session = requests.sessions.Session()
    adapter = requests.adapters.HTTPAdapter(max_retries=0)
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    try:
        response = session.head(url, timeout=timeout)
    except Exception as e:
        logger.debug(e)
        queue.put(False)
        return

    queue.put(response)


if __name__ == '__main__':
    sys.exit(main())