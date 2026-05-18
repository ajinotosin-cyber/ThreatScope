import re

PATTERNS={

"Brute Force":

r"failed login|authentication failed",

"Malware":

r"malware|trojan|virus",

"Port Scan":

r"scan|nmap",

"Privilege Escalation":

r"sudo|admin access"

}

def parse_logs(text):

    findings=[]

    text=text.lower()

    for k,v in PATTERNS.items():

        if re.search(v,text):

            findings.append(k)

    return findings
