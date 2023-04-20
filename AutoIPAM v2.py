from zeep import Client
import ipaddress
import csv
import os
import json
import time

with open("config.json", "r") as config_file:
    config = json.load(config_file)

class Block:
    def __init__(self, bluecat_manager):
        self.bluecat_manager = bluecat_manager

    def ProcessEntry(self, entry):
        network = ipaddress.ip_network(entry[2], strict=False)
        chain = self.bluecat_manager.utils.dig(bluecat_manager.client, network.network_address, "IP4Block")

        if self.bluecat_manager.utils.checkIfExists(entry[2], chain):
            print(f"Block {entry[2]} already exists.")
        else:
            print(f"Added {entry[1]} block to {entry[2]}.")
            self.bluecat_manager.client.service.addIP4BlockByCIDR(chain[-1]['id'], entry[2], f"name={entry[1]}|" + self.bluecat_manager.block_properties)

class Network:
    def __init__(self, bluecat_manager):
        self.bluecat_manager = bluecat_manager

    def ProcessEntry(self, entry):
        network = ipaddress.ip_network(entry[2], strict=False)
        block_chain = self.bluecat_manager.utils.dig(bluecat_manager.client, network.network_address, "IP4Block")
        network_chain = self.bluecat_manager.utils.dig(bluecat_manager.client, network.network_address, "IP4Network", block_chain[-1]['id'])

        if len(entry) != 4:
            gateway = ''
        else:
            gateway = f'gateway={entry[3]}|'

        if self.bluecat_manager.utils.checkIfExists(entry[2], network_chain):
            print(f"Network {entry[2]} already exists.")
        else:
            network_id = self.bluecat_manager.client.service.addIP4Network(block_chain[-1]['id'], entry[2], f'name={entry[1]}|{gateway}' + self.bluecat_manager.block_properties)
            print(f"Added {entry[1]} network to {entry[2]}.")

class Host:
    def __init__(self, bluecat_manager):
        self.bluecat_manager = bluecat_manager

    def ProcessEntry(self, entry):
        valid = self.checkIfValidHostname(entry[1])
        if valid[0]:
            block_chain = self.bluecat_manager.utils.dig(bluecat_manager.client, entry[2], "IP4Block")
            network_chain = self.bluecat_manager.utils.dig(bluecat_manager.client, entry[2], "IP4Network", block_chain[-1]['id'])

            self.addHost(self.bluecat_manager.top_level_view_id, network_chain[-1]['id'], entry[1], entry[2])
        else:
            print(valid[1])

    def updateRecordWithIP(self, data, new_address):
        """Update a record with a new IP address."""
        # Split the properties string into a list of key-value pairs
        properties_list = data['properties'].split('|')

        # Iterate through the list and find the 'addresses' key
        for i, prop in enumerate(properties_list):
            if prop.startswith('addresses='):
                addresses = prop.split('=')[1]
                # Add the new address
                updated_addresses = addresses + ',' + new_address
                # Update the properties list with the new addresses string
                properties_list[i] = f'addresses={updated_addresses}'
                break

        # Join the properties list back into a single string
        updated_properties = '|'.join(properties_list)

        # Update the data dictionary with the modified properties string
        data['properties'] = updated_properties

        return data

    def buildDnsDict(self, host_area):
        """Populate the DNS dictionary with all hosts in a specific zone."""
        for zone in self.bluecat_manager.utils.getEntities(self.bluecat_manager.client, self.bluecat_manager.ntlb_view_id, "Zone"):
            if zone['name'].upper() == host_area:
                subzone = zone['id']

        if subzone == 0:
            return False

        if host_area in self.bluecat_manager.dns_dict:
            self.bluecat_manager.dns_dict[host_area].extend(self.bluecat_manager.utils.getEntities(self.bluecat_manager.client, subzone, "HostRecord", end=9999))
        else:
            self.bluecat_manager.dns_dict[host_area] = self.bluecat_manager.utils.getEntities(self.bluecat_manager.client, subzone, "HostRecord", end=9999)

        self.bluecat_manager.full_updates += [host_area] # Add this domain to the list that have had full dictionaries built

    def addToDict(self, hostname, _id):
        data = self.bluecat_manager.client.service.getEntityById(_id)
        elements = hostname.split('.')
        host_area = elements[-2].upper()
        
        if host_area in self.bluecat_manager.dns_dict:
            self.bluecat_manager.dns_dict[host_area].append(data)
        else:
            self.bluecat_manager.dns_dict[host_area] = [data]

    def findExistingHostID(self, hostname):
        """Find the object ID of an existing host."""
        elements = hostname.split('.')
        host_area = elements[-2]
        modified_elements = elements[:-2]
        host_without_zone = '.'.join(modified_elements)
        subzone = 0

        if host_area.upper() not in self.bluecat_manager.full_updates:
            print(f"Building dictionary for '{host_area}.ntlb'")
            self.buildDnsDict(host_area.upper())

        for host in self.bluecat_manager.dns_dict[host_area.upper()]:
            if host['name'] is not None:
                if host_without_zone.upper() == host['name'].upper():
                    return host['id']

    def IsIpAlreadyAssigned(self, ip, net_id):
        """ Check to see if the IP address in the range is already assigned """
        existing_allocations = self.bluecat_manager.utils.getEntities(self.bluecat_manager.client, net_id, "IP4Address")
        if existing_allocations:
            for entity in self.bluecat_manager.utils.getEntities(self.bluecat_manager.client, net_id, "IP4Address"):
                if ip == self.bluecat_manager.utils.extractAddress(entity['properties']):
                    return True
        return False
    
    def addNewHostRecord(self, view_id, _name, ip):
        """ Add a host record given the host doesn't already exist and the IP isn't already assigned """
        add_id = self.bluecat_manager.client.service.addHostRecord(view_id, _name, ip, "0", "reverseRecord=true")
        # Add the new host record into the dictionary
        self.addToDict(_name, add_id)
        print(f"Assigned {_name} to {ip}.")

    def updateHostRecord(self, _name, ip):
        """ Finds the existing host record that is clashing and updates the record with the new IPs.
            Will call updateRecordWithIP() which will create the updated record. """
        host_id = self.findExistingHostID(_name)
        host = self.bluecat_manager.client.service.getEntityById(host_id)
        self.bluecat_manager.client.service.update(self.updateRecordWithIP(host, ip))
        print(f"Assigned {_name} to {ip}. Existing record with IP added.")

    def addHost(self, view_id, net_id, _name, ip):
        """Add a host with a specific IP address.
            Will do checks to ensure IPs aren't already assigned and will update an existing record if required. """
        if self.IsIpAlreadyAssigned(ip, net_id):
            print(f"Address ({ip}) already assigned.")
        else:
            try:
                self.addNewHostRecord(view_id, _name, ip)
            except Exception as e:
                self.updateHostRecord(_name, ip)

    def checkIfHostnameHasTwoDomains(self, hostname):
        if hostname.count(".") < 2:
            return False
        return True

    def checkIfHostnameIsInNTLB(self, hostname):
        elements = hostname.split('.')
        domain = elements[-1]
        if domain.upper() != "NTLB":
            return False
        return True

    def checkIfHostnameHasValidSubdomain(self, hostname):
        host_area_exists = False
        elements = hostname.split('.')
        host_area = elements[-2]
        for zone in self.bluecat_manager.utils.getEntities(self.bluecat_manager.client, self.bluecat_manager.ntlb_view_id, "Zone"):
            if zone['name'].upper() == host_area.upper():
                host_area_exists = True
        if not host_area_exists:
            return False
        return True

    def checkIfValidHostname(self, hostname):
        """Check if the given hostname is valid."""
        return (
            (False, f"Did you forget to add the full subdomain + domain for this hostname ({hostname})?")
            if not self.checkIfHostnameHasTwoDomains(hostname)
            else (
                (False, f"This hostname ({hostname}) is not part of the 'ntlb' domain.")
                if not self.checkIfHostnameIsInNTLB(hostname)
                else (
                    (False, f"This subdomain doesn't exist. Please check the hostname ({hostname}).")
                    if not self.checkIfHostnameHasValidSubdomain(hostname)
                    else (True, "")
                )
            )
        )

class BluecatUtils:
    @staticmethod
    def checkIfExists(subnet, chain):
        """Check if a subnet is in a chain."""
        exists = False
        for link in chain:
            if subnet == BluecatUtils.extractCidr(link['properties']):
                exists = True
        return exists

    @staticmethod
    def extractCidr(properties):
        """Get the CIDR out of the properties field."""
        for prop in properties.split('|'):
            if prop.startswith('CIDR='):
                return prop.replace('CIDR=', '')

    @staticmethod
    def extractAddress(properties):
        """Get the address out of the properties field."""
        for prop in properties.split('|'):
            if prop.startswith('address='):
                return prop.replace('address=', '')

    @staticmethod
    def extractStartEnd(properties):
        """Extract the start and end of a range from the properties field."""
        start, end = None, None
        for prop in properties.split('|'):
            if prop.startswith('start='):
                start = prop.replace('start=', '')
            elif prop.startswith('end='):
                end = prop.replace('end=', '')
        return start, end

    @staticmethod
    def dig(client, ip, _type, begin_from=5):
        """
        Digs through all layers of objects to find the lowest level object that the IP fits in.
        
        Args:
            ip (str): IP address to search for.
            _type (str): Type of object to dig through.
            begin_from (int, optional): Beginning object ID. Defaults to 5.
        
        Returns:
            list: A chain of matching objects.
        """
        chain = []
        result = BluecatUtils.getEntities(client, begin_from, _type)
        while True:
            end_of_chain, result, chain = BluecatUtils.processResult(client, result, ip, _type, chain)
            if end_of_chain:
                break
        return chain

    @staticmethod
    def processResult(client, result, ip, _type, chain):
        """
        Process the result of a getEntities call, update the chain and return the next set of entities.
        
        Args:
            result (list): The result of a getEntities call.
            ip (str): IP address to search for.
            _type (str): Type of object to dig through.
            chain (list): The current chain of matching objects.
            
        Returns:
            tuple: A tuple containing a boolean indicating if the end of the chain is reached, 
                   the next set of entities, and the updated chain.
        """
        end_of_chain = True
        if result:
            for obj in result:
                cidr, start, end = BluecatUtils.extractCidrStartEnd(obj['properties'])
                if BluecatUtils.isIpInBlock(ip, cidr, start, end):
                    chain += [obj]
                    next_id = obj['id']
                    end_of_chain = False
                    result = BluecatUtils.getEntities(client, next_id, _type)
                    break
        return end_of_chain, result, chain

    @staticmethod
    def extractCidrStartEnd(properties):
        """
        Extract the CIDR, start, and end from the properties field.
        
        Args:
            properties (str): The properties field containing the CIDR, start, and end values.
        
        Returns:
            tuple: A tuple containing the CIDR, start, and end values (if present).
        """
        cidr, start, end = None, None, None
        if "CIDR" in properties:
            cidr = BluecatUtils.extractCidr(properties)
        elif "start" in properties:
            start, end = BluecatUtils.extractStartEnd(properties)
        return cidr, start, end

    @staticmethod        
    def getEntities(client, _id, _type, end=999):
        """Get entities from Bluecat API."""
        return client.service.getEntities(_id, _type, 0, end)

    @staticmethod
    def isIpInBlock(ip, block=None, start=None, end=None):
        """Check if an IP is in a specific block (or start/end range)."""
        if block:
            ip_obj = ipaddress.ip_address(ip)
            block_obj = ipaddress.ip_network(block)
            return ip_obj in block_obj
        if start:
            ip_obj = ipaddress.ip_address(ip)
            start_obj = ipaddress.ip_address(start)
            end_obj = ipaddress.ip_address(end)
            return start_obj <= ip_obj <= end_obj
    
class BluecatManager:
    def __init__(self, username, password, bam_hostname):
        self.client = Client(f"http://{bam_hostname}/Services/API?wsdl")
        self.session_id = self.client.service.login(username, password)
        self.dns_dict = {}
        self.full_updates = [] # Which domains have had a full dictionary built
        self.top_level_view_id = config["top_level_view_id"]
        self.ntlb_view_id = config["ntlb_view_id"]
        self.block_properties = f"allowDuplicateHost=disable|inheritAllowDuplicateHost=true|pingBeforeAssign=disable|inheritPingBeforeAssign=true|inheritDefaultDomains=true|defaultView={self.top_level_view_id}|inheritDefaultView=true|inheritDNSRestrictions=true|"

        self.block = Block(self)
        self.network = Network(self)
        self.host = Host(self)
        self.utils = BluecatUtils()

    def logout(self):
        self.client.service.logout()


file_path = ''
username = ''
password = os.environ.get("BLUECAT_API_PASSWORD")
server_ip = ''
bluecat_manager = BluecatManager(username, password, server_ip)

with open(file_path, mode='r', newline='') as csvfile:
    csv_reader = csv.reader(csvfile)
    data = [row for row in csv_reader]

entry_type_mapping = {
    "Block": bluecat_manager.block.ProcessEntry,
    "Network": bluecat_manager.network.ProcessEntry,
    "Host": bluecat_manager.host.ProcessEntry,
}

for entry in data:
    process_entry_func = entry_type_mapping.get(entry[0])
    if process_entry_func:
        process_entry_func(entry)
    else:
        print(f"Unknown entry type: {entry[0]}")
    time.sleep(1) # Adding just in case of rate limiting

bluecat_manager.logout()
