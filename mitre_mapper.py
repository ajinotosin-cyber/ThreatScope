MITRE={

"Brute Force":

"T1110",

"Privilege Escalation":

"T1068",

"Port Scan":

"T1046",

"Malware":

"T1204"

}

def map_attack(event):

    return MITRE.get(

        event,

        "Unknown"

    )
