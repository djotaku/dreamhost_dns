""" This is a simple python script for updating the
    DNS Custom Records in Dreamhost Nameservers using
    Dreamhost API commands.

    Provided under the MIT License (MIT). See LICENSE for details.

    """


import json
import re
import requests
import sys
import syslog
import uuid
import logging

logging.basicConfig(level=logging.INFO)

# Set this to 1 if you want to update IPv6 record.
CHECK_IP_V6 = 0


def rand_uuid():
    return str(uuid.uuid4())


def get_dns_records(api_key):
    return speak_to_dreamhost("dns-list_records", api_key)


def del_dns_record(domain, dns_ip, api_key, protocol='ip'):
    current_ip = dns_ip
    rec_type = 'AAAA' if protocol == 'ipv6' else 'A'
    logging.debug('The current %s IP is: %s', protocol, current_ip)
    if current_ip == '':
        logging.error("Can't delete IP, value passed is empty")
        sys.exit("Weird")
    command = "dns-remove_record&record=" + domain + "&type=" + rec_type + "&value=" + current_ip
    response = speak_to_dreamhost(command, api_key)
    if response.get('result') == 'error':
        logging.error('Error while deleting %s record: \n %s', protocol, response)
    logging.debug('Tried to del %s record and here is what Dreamhost responded: \n %s', protocol, response)


def add_dns_record(domain: str, new_ip_address: str, api_key: str, protocol='ip'):
    address = new_ip_address
    rec_type = "AAAA" if protocol == "ipv6" else "A"
    logging.debug('Our new %s address is: %s', protocol, address)
    command = "dns-add_record&record=" + domain + "&type=" + rec_type + "&value=" + address
    response = speak_to_dreamhost(command, api_key)
    if response.get('result') == 'error':
        logging.error('Error while adding %s record: \n %s', protocol, response)
    elif response.get('result') == 'success':
        logging.info("Record supposedly updated")
    logging.debug('Tried to add %s record and Dreamhost responded with: \n %s', protocol, response)


def update_dns_record(domain: str, dns_ip: str, new_ip_address: str, api_key, protocol='ip'):
    if dns_ip:
        del_dns_record(domain, dns_ip, api_key, protocol)
    add_dns_record(domain, new_ip_address, api_key, protocol)


def make_url_string(command, api_key):
    """"str->str"""
    return "/?key=" + api_key + "&cmd=" + command + "&unique_id=" + rand_uuid() + "&format=json"


def speak_to_dreamhost(command, api_key):
    """Send command to dreamhost and get back the results as a JSON object."""
    api_url = "api.dreamhost.com"
    logging.debug('Will try to speak to Dreamhost, here is what I will tell: %s', command)
    substring = make_url_string(command, api_key)
    result = requests.get(f"https://{api_url}{substring}")
    logging.debug(f"Here is what Dreamhost responded: {result.json()}")
    return result.json()


def get_host_ip_address(protocol='ip'):
    if protocol == 'ipv6':
        ip_address = requests.get('http://checkipv6.dyndns.com')
    else:
        ip_address = requests.get('http://checkip.dyndns.com')
    body = clean_html(ip_address.text)
    ip_addr_list = body.rsplit()
    return ip_addr_list[-1]


def clean_html(raw_html):
    clean = re.compile('<.*?>')
    return re.sub(clean, '', raw_html)


def make_it_so(api_key: str, domains: str):
    if api_key == '' or domains is False:
        msg = 'API_Key and/or domain empty. Edit settings.json and try again.'
        syslog.syslog(syslog.LOG_ERR, msg)
        sys.exit(msg)
    current_dns_records = get_dns_records(api_key)
    domain_dns_ip_pairs = [(record.get("record"), record.get("value"))
                           for record in current_dns_records.get('data')
                           if record.get("record") in domains]
    for domain_to_update in domain_dns_ip_pairs:
        dns_ip = domain_to_update[1]
        domain = domain_to_update[0]
        logging.debug('dns_ip: %s', dns_ip)
        new_ip_address = get_host_ip_address()
        logging.debug('new_ip_address: %s', new_ip_address)
        if dns_ip != new_ip_address:
            logging.info('Address different, will try to update.')
            logging.info(f"{domain} should go from {dns_ip} to {new_ip_address}")
            update_dns_record(domain, dns_ip, api_key, new_ip_address)
        else:
            logging.info('IP Record up-to-date.')
        if CHECK_IP_V6 == 1:
            new_ip_address = get_host_ip_address('ipv6')
            if dns_ip != new_ip_address:
                update_dns_record(domain, dns_ip, api_key, new_ip_address, 'ipv6')
            else:
                logging.info('IPv6 Record up-to-date.')


def gather_information():
    """Read in data from settings.json"""
    with open("settings.json", 'r') as file:
        return json.load(file)


if __name__ == "__main__":
    settings = gather_information()
    the_api_key = settings.get("api_key")
    our_domains = settings.get("domains")
    make_it_so(the_api_key, our_domains)
