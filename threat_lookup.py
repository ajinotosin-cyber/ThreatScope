import requests
import os
from dotenv import load_dotenv

load_dotenv()

VT_KEY = os.getenv("VT_API_KEY")
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")
OTX_KEY = os.getenv("OTX_API_KEY")


def virustotal_lookup(ip):

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
        "x-apikey": VT_KEY
    }

    r = requests.get(
        url,
        headers=headers
    )

    if r.status_code == 200:

        data = r.json()

        stats = data["data"]["attributes"][
            "last_analysis_stats"
        ]

        malicious = stats.get(
            "malicious",
            0
        )

        country = data["data"][
            "attributes"
        ].get(
            "country",
            "Unknown"
        )

        return malicious,country

    return 0,"Unknown"


def abuse_lookup(ip):

    url="https://api.abuseipdb.com/api/v2/check"

    headers={

        "Key":ABUSE_KEY,

        "Accept":"application/json"

    }

    params={

        "ipAddress":ip,

        "maxAgeInDays":"90"

    }

    r=requests.get(
        url,
        headers=headers,
        params=params
    )

    if r.status_code==200:

        score=r.json()["data"][
            "abuseConfidenceScore"
        ]

        return score

    return 0


def classify_ip(ip):

    vt,country=virustotal_lookup(ip)

    abuse=abuse_lookup(ip)

    if abuse>80 or vt>10:

        threat="Malware"

        severity="Critical"

    elif abuse>40:

        threat="Intrusion"

        severity="High"

    elif abuse>10:

        threat="Phishing"

        severity="Medium"

    else:

        threat="Safe"

        severity="Low"

    return {

        "country":country,

        "vt":vt,

        "abuse":abuse,

        "threat":threat,

        "severity":severity

    }
