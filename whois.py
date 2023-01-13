from ipwhois import IPWhois
from pprint import pprint
import socket

class Whois:
    def __init__(self, domain):
        self.domain = domain
        try:
            self.ip = socket.gethostbyname(self.domain)
        except socket.gaierror as e:
            self.ip = None
            print(f"error,value:{e}")
   
    def getLookupResults(self):
        obj = IPWhois(self.ip) if self.ip else None
        #change bootstrap to False if you want ASN Data, does slow things down though!
        if obj:
            return(obj.lookup_rdap(depth=1))
        else:
            return None

#########################################################
#   getAbuseInfo(domain):
#       domain: domain (str) to retrieve abuse info for
#   Descr:
#       - Create the whois object supplying the domain
#       - Perform the actual abuse info lookup operation
#       - If we find an entry with an abuse role labeled, return
#   Return:
#       list of email addresses (list of strings)
#       all failures return None
#########################################################
def getAbuseInfo(domain):
    whois_obj = Whois(domain)
    if not whois_obj: return None
    results = whois_obj.getLookupResults()
    if not results: return None
    
    for entry in results['objects']:
        entry_result = results['objects'][entry] if entry else None
        entry_roles = entry_result['roles'] if entry_result else None
        if entry_roles and ('abuse' in entry_roles):
            return [email_addr['value'] for email_addr in entry_result['contact']['email']]