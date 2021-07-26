""" This is a simple python script for updating the
    DNS Custom Records in Dreamhost Nameservers using
    Dreamhost API commands.

    Provided under the MIT License (MIT). See LICENSE for details.

    """


import json
import re
import requests
import sys
import uuid
import logging

dreamhost_log = logging.getLogger("Dreamhost_DNS")
dreamhost_log.setLevel(logging.DEBUG)
stream_handler = logging.StreamHandler(stream=sys.stdout)
stream_handler.setLevel(logging.INFO)
stream_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
dreamhost_log.addHandler(stream_handler)
file_handler = logging.FileHandler("dreamhost_dns_log.txt")
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
dreamhost_log.addHandler(file_handler)


# Set this to 1 if you want to update IPv6 record.
CHECK_IP_V6 = 0


def rand_uuid():
    return str(uuid.uuid4())


def get_dns_records(api_key):
    return speak_to_dreamhost("dns-list_records", api_key)


def del_dns_record(domain, dns_ip, api_key, protocol='ip'):
    current_ip = dns_ip
    rec_type = 'AAAA' if protocol == 'ipv6' else 'A'
    dreamhost_log.debug(f'The current {protocol} IP for {domain} is: {current_ip}')
    if current_ip == '':
        dreamhost_log.error(f"Can't delete IP for {domain}, value passed is empty")
        sys.exit("Weird")
    command = "dns-remove_record&record=" + domain + "&type=" + rec_type + "&value=" + current_ip
    response = speak_to_dreamhost(command, api_key)
    if response.get('result') == 'error':
        dreamhost_log.error(f'Error while deleting {protocol} record for {domain}: {response}')
    dreamhost_log.debug(f'Tried to del {protocol} record for {domain} and Dreamhost responded: {response}')


def add_dns_record(domain: str, new_ip_address: str, api_key: str, protocol='ip'):
    address = new_ip_address
    rec_type = "AAAA" if protocol == "ipv6" else "A"
    dreamhost_log.debug(f'Our new {protocol} address for {domain} is {address}')
    command = "dns-add_record&record=" + domain + "&type=" + rec_type + "&value=" + address
    response = speak_to_dreamhost(command, api_key)
    if response.get('result') == 'error':
        dreamhost_log.error(f'Error while adding {protocol} record for {domain}: \n {response=}')
    elif response.get('result') == 'success':
        dreamhost_log.info(f"Record for {domain} was updated with {new_ip_address=}")
    dreamhost_log.debug(f'Tried to add {protocol} record for {domain} and Dreamhost responded with: {response}')
    return response.get('result')


def update_dns_record(domain: str, dns_ip: str, new_ip_address: str, api_key, protocol='ip'):
    """Add the new DNS record and remove the old one."""
    add_dns_record_result = add_dns_record(domain, new_ip_address, api_key, protocol)
    if dns_ip and add_dns_record_result == "success":
        del_dns_record(domain, dns_ip, api_key, protocol)


def make_url_string(command, api_key):
    """"str->str"""
    return "/?key=" + api_key + "&cmd=" + command + "&unique_id=" + rand_uuid() + "&format=json"


def speak_to_dreamhost(command, api_key):
    """Send command to dreamhost and get back the results as a JSON object."""
    api_url = "api.dreamhost.com"
    dreamhost_log.debug(f'I will send {command} to Dreamhost')
    substring = make_url_string(command, api_key)
    result = requests.get(f"https://{api_url}{substring}")
    dreamhost_log.debug(f"Here is what Dreamhost responded: {result.json()}")
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
        dreamhost_log.error(msg)
        sys.exit(msg)
    current_dns_records = get_dns_records(api_key)
    domain_dns_ip_pairs = [(record.get("record"), record.get("value"))
                           for record in current_dns_records.get('data')
                           if record.get("record") in domains]
    new_ip_address = get_host_ip_address()
    for domain_to_update in domain_dns_ip_pairs:
        dns_ip = domain_to_update[1]
        domain = domain_to_update[0]
        dreamhost_log.debug(f'Current IP = {dns_ip}')
        dreamhost_log.debug(f'new_ip_address: {new_ip_address}')
        if dns_ip != new_ip_address:
            logging.info('Address different, will try to update.')
            logging.info(f"{domain} should go from {dns_ip} to {new_ip_address}")
            update_dns_record(domain, dns_ip, new_ip_address, api_key)
        else:
            dreamhost_log.info(f'IP Record for {domain} is up-to-date.')
        if CHECK_IP_V6 == 1:
            new_ip_address = get_host_ip_address('ipv6')
            if dns_ip != new_ip_address:
                update_dns_record(domain, dns_ip, new_ip_address, api_key, 'ipv6')
            else:
                dreamhost_log.info(f'IPv6 Record for {domain} is up-to-date.')
    # perhaps you have some new domains or something happened to delete the ones you care about
    updated_domains = [domain[0] for domain in domain_dns_ip_pairs]
    new_dns_to_add = [domain for domain in domains if domain not in updated_domains]
    for new_domain in new_dns_to_add:
        add_dns_record(new_domain, new_ip_address, api_key)


def gather_information():
    """Read in data from settings.json"""
    with open("settings.json", 'r') as file:
        return json.load(file)


if __name__ == "__main__":
    settings = gather_information()
    the_api_key = settings.get("api_key")
    our_domains = settings.get("domains")
    make_it_so(the_api_key, our_domains)
