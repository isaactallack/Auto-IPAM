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

            # Only send the comments and add type if they are in the entry and passed validation
            if entry[3] and entry[4] and self.areCommentsSectionValid(entry[3], entry[4]):
                self.addHost(self.bluecat_manager.top_level_view_id, network_chain[-1]['id'], entry[1], entry[2], entry[3], entry[4])
            else:
                # Otherwise, if they are in the entry but haven't passed verification, send the warning message and then send without comments
                if entry[3] and entry[4]:
                    print(f"Excluded comments from ({entry[1]}, {entry[2]}) as it hasn't passed validation.")
                self.addHost(self.bluecat_manager.top_level_view_id, network_chain[-1]['id'], entry[1], entry[2])
        else:
            print(valid[1])

    def areCommentsSectionValid(self, comments, comments_action):
        """Checks if the comments section is valid before sending off to other functions

        Args:
            comments (str): The comments to be added to the host.
            comments_action(str): The action for the comment (add, append or replace).

        Returns:
            True: the comments and comments_action is valid
            False: the comment or action isn't valid
        """

        valid_actions = ['add', 'append', 'replace']

        if comments_action.lower() not in valid_actions:
            return False
        if "|" in comments:
            return False

        return True

    def updateRecord(self, data, new, _type, delim = ",", replace = False):
        """Modifies the properties field of a host record with new data

        Args:
            data (dic): Dictionary containing the entry for a specific host record
            new (str): The data to update the record with, could either be an additional IP address, a new comment or something else completely
            _type (str): The type of field to update e.g. "addresses", "comments" etc.
            delim (str, optional): If the operation is to add (replace = False) then define the delimiter between exsiting and new values. "," by default but might want "\r\n" for new line.
            replace (bool, optional): If replace is set to true, the field in question will be overwritten, otherwise it'll just be added to

        Returns:
            data (dic) : The updated dictionary containing the new data
        """
        _type = f"{_type}="
        # Split the properties string into a list of key-value pairs
        properties_list = data['properties'].split('|')

        # Iterate through the list and find the '_type' key
        for i, prop in enumerate(properties_list):
            if prop.startswith(_type):
                old = prop.split('=')[1]
                # Add the new details
                if replace:
                    updated = new
                else:
                    updated = old + delim + new
                # Update the properties list with the new string
                properties_list[i] = f'{_type}{updated}'
                break

        # Join the properties list back into a single string
        updated_properties = '|'.join(properties_list)

        # Update the data dictionary with the modified properties string
        data['properties'] = updated_properties

        return data

    def buildDnsDict(self, host_area):
        """Populate the DNS dictionary with all hosts in a specific zone.

        Args:
            host_area (str): The name of the host area that a dictionary should be created from e.g. ""

        Returns:
            None
        """
        for zone in self.bluecat_manager.utils.getEntities(self.bluecat_manager.client, self.bluecat_manager.view_id, "Zone"):
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
        """ Required to update the dictionary on the fly, not only once at the beginning.
            This is important as it means updated records will not be overwritten and hosts that have been added after the dictionary creation will be seen

        Args:
            hostname (str): The hostname of the record to be added to the dictionary
            _id (int): The Bluecat ID value of the record to be added to the dictionary

        Returns:
            None
        """
        data = self.bluecat_manager.client.service.getEntityById(_id)
        elements = hostname.split('.')
        host_area = elements[-2].upper()
        
        if host_area in self.bluecat_manager.dns_dict:
            self.bluecat_manager.dns_dict[host_area].append(data)
        else:
            self.bluecat_manager.dns_dict[host_area] = [data]

    def findExistingHostID(self, hostname):
        """ Finds the object ID of an existing host

        Args:
            hostname (str): The hostname of the record of which the ID needs to be found

        Returns:
            id (int): The Bluecat ID of the host
        """
        elements = hostname.split('.')
        host_area = elements[-2]
        modified_elements = elements[:-2]
        host_without_zone = '.'.join(modified_elements)
        subzone = 0

        if host_area.upper() not in self.bluecat_manager.full_updates:
            print(f"Building dictionary for '{host_area}.'")
            self.buildDnsDict(host_area.upper())

        for host in self.bluecat_manager.dns_dict[host_area.upper()]:
            if host['name'] is not None:
                if host_without_zone.upper() == host['name'].upper():
                    return host['id']

    def IsIpAlreadyAssigned(self, ip, net_id):
        """ Check to see if the IP address in the range is already assigned

        Args:
            ip (str): The IP address of the record
            net_id (int): The Bluecat ID of the network range

        Returns:
            True: The IP is already assigned to one of the addresses in the network range
            False: The IP address has not yet been assigned to
        """
        existing_allocations = self.bluecat_manager.utils.getEntities(self.bluecat_manager.client, net_id, "IP4Address")
        if existing_allocations:
            for entity in self.bluecat_manager.utils.getEntities(self.bluecat_manager.client, net_id, "IP4Address"):
                if ip == self.bluecat_manager.utils.extractAddress(entity['properties']):
                    return True
        return False

    def updateComments(self, host_id, name, data, comments, comments_action):
        """Updates the comments properties for an existing entry based on the required action

        Args
            host_id (int): ID of the host that the comments are being edited on.
            name (str): The full name of the host that the comments are being edited on (including domains).
            data (dic): The full data dictionary of the host provided.
            comments (str): The comments to be added to the host.
            comments_action(str): The action for the comment (add, append or replace).

        Returns:
            None
        """
        
        properties = data['properties']
        comments_key = "comments"

        if comments_action.lower() == "add":
            if comments_key not in properties:
                data = self.addComments(data, comments)
            else:
                pass
        elif comments_action.lower() == "append":
            data = self.appendComments(data, comments, properties, comments_key)
        elif comments_action.lower() == "replace":
            data = self.replaceComments(data, comments, properties, comments_key)
        else:
            raise ValueError("Invalid comments_action value. Allowed values are 'Add', 'Append', 'Replace'.")

        self.bluecat_manager.client.service.update(data)
        self.addToDict(name, host_id)

    def addComments(self, data, comments):
        """ Updates the data field by creating, and adding to the comments field in the properties

        Args:
            data (dic): The full data dictionary of the host provided.
            comments (str): The comments to be added to the host.

        Returns:
            data (dic): The data dictionary containing the comments attribute
        """
        data['properties'] += f"|comments={comments}"
        return data

    def appendComments(self, data, comments, properties, comments_key):
        """ Tries to append the comments to the data field if it already has comments
            If it doesn't, it calls addComments() to create and add the comments

        Args:
            data (dic): The full data dictionary of the host provided.
            comments (str): The comments to be added to the host.
            properties (str): The properties field within the host record
            comments_key (str): The key to look out for in the properties field (e.g. "comments")

        Returns:
            data (dic): The data dictionary containing the comments attribute
        """
        if comments_key in properties:
            data = self.updateRecord(data, comments, comments_key, delim="\r\n", replace=False)
        else:
            self.addComments(data, comments)
        return data

    def replaceComments(self, data, comments, properties, comments_key):
        """ Tries to replace the comments to the data field if it already has comments
            If it doesn't, it calls addComments() to create and add the comments

        Args:
            data (dic): The full data dictionary of the host provided.
            comments (str): The comments to be added to the host.
            properties (str): The properties field within the host record
            comments_key (str): The key to look out for in the properties field (e.g. "comments")

        Returns:
            data (dic): The data dictionary containing the comments attribute
        """
        if comments_key in properties:
            data = self.updateRecord(data, comments, comments_key, replace=True)
        else:
            self.addComments(data, comments)
        return data
                
    def addNewHostRecord(self, view_id, _name, ip, comments):
        """ Add a host record, given the host doesn't already exist and the IP isn't already assigned
            If there are comments to add, then add them, otherwise just create the host record without comments

        Args:
            view_id (int): The Bluecat view ID
            _name (str): The name of the record to add
            ip (str): The initial IP address to assign to the host record
            comments (str): The comments to add to the host record

        Returns:
            None
        """
        if comments:
            add_id = self.bluecat_manager.client.service.addHostRecord(view_id, _name, ip, "0", f"reverseRecord=true|comments={comments}")
        else:
            add_id = self.bluecat_manager.client.service.addHostRecord(view_id, _name, ip, "0", f"reverseRecord=true")
        # Add the new host record into the dictionary
        self.addToDict(_name, add_id)
        print(f"Assigned {_name} to {ip}.")

    def updateHostRecord(self, _name, ip, comments, comments_action):
        """ Finds the existing host record that is clashing and updates the record with the new IPs and comments.
            Will call updateRecordWithIP() which will create the updated record.
            If comments required, will call updateComments() which will sort out comments for the record.

        Args:
            _name (str): The name of the record to update
            ip (str): The new IP address to assign to the host record
            comments (str): The comments to add to the host record
            comments_action (str): How to add the comments (Should they only be added if there are none existing? Should they append? Should they replace existing?)

        Returns:
            None
        """
        host_id = self.findExistingHostID(_name)
        host = self.bluecat_manager.client.service.getEntityById(host_id)
        self.bluecat_manager.client.service.update(self.updateRecord(host, ip, "addresses"))

        if comments and comments_action:
            self.updateComments(host_id, _name, host, comments, comments_action)
            
        print(f"Assigned {_name} to {ip}. Existing record with IP added.")

    def addHost(self, view_id, net_id, _name, ip, comments = None, comments_action = None):
        """ Tries to add a host with a specific IP address.
            Initially just tries to add a new host record, failing this, will try to update the existing record.
            
        Args:
            view_id (int): The Bluecat view ID
            net_id (int): The Bluecat ID for the network the host is being added to
            _name (str): The name of the record to add (or update if the case may be)
            ip (str): The IP address to assign to the host record
            comments (str, optional): The comments to add to the host record
            comments_action (str, optional): How to add the comments (Should they only be added if there are none existing? Should they append? Should they replace existing?)

        Returns:
            None
        """
        if self.IsIpAlreadyAssigned(ip, net_id):
            print(f"Address ({ip}) already assigned.")
        else:
            try:
                self.addNewHostRecord(view_id, _name, ip, comments)
            except Exception as e:
                self.updateHostRecord(_name, ip, comments, comments_action)

    def checkIfHostnameHasTwoDomains(self, hostname):
        """ Checks if a hostname has two layers of domains
            
        Args:
            hostname (str): The hostname of the record to add

        Returns:
            True: There is a parent domain and a subdomain
            False: There aren't enough layers of domains
        """
        if hostname.count(".") < 2:
            return False
        return True

    def checkIfHostnameIsIn(self, hostname):
        """ Checks if a hostname is in the right parent domain
            
        Args:
            hostname (str): The hostname of the record to add

        Returns:
            True: Host is in the correct parent domain
            False: Host isn't in the correct parent domain
        """        
        elements = hostname.split('.')
        domain = elements[-1]
        if domain.upper() != "":
            return False
        return True

    def checkIfHostnameHasValidSubdomain(self, hostname):
        """ Checks if a hostname has a valid subdomain
            
        Args:
            hostname (str): The hostname of the record to add

        Returns:
            True: Host has a valid subdomain
            False: Host has an invalid subdomain
        """  
        host_area_exists = False
        elements = hostname.split('.')
        host_area = elements[-2]
        for zone in self.bluecat_manager.utils.getEntities(self.bluecat_manager.client, self.bluecat_manager.view_id, "Zone"):
            if zone['name'].upper() == host_area.upper():
                host_area_exists = True
        if not host_area_exists:
            return False
        return True

    def checkIfValidHostname(self, hostname):
        """ Calls all hostname validity functions to determine if the hostname is good
            
        Args:
            hostname (str): The hostname of the record to add

        Returns:
            True: Host is good to go!
            False: Host is invalid in someway
        """  
        return (
            (False, f"Did you forget to add the full subdomain + domain for this hostname ({hostname})?")
            if not self.checkIfHostnameHasTwoDomains(hostname)
            else (
                (False, f"This hostname ({hostname}) is not part of the parent domain.")
                if not self.checkIfHostnameIsIn(hostname)
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
        self.view_id = config["view_id"]
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
    time.sleep(1) # Adding just to avoid hitting server too hard - probably fine but I'm in no rush

bluecat_manager.logout()
