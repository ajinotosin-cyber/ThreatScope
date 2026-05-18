import requests
from ipwhois import IPWhois

ABUSEIPDB_KEY="b9d87a7816b8685cbb52bde9a01621096632cb8c03a27aaafb02caaff979f004af2baf22ebcefff3"

def investigate_ip(ip):

    result={

        "ioc":ip,
        "country":"Unknown",
        "abuse_score":0,
        "threat":"Safe"

    }

    try:

        geo=IPWhois(ip)

        lookup=geo.lookup_rdap()

        result["country"]=lookup.get(
            "asn_country_code",
            "Unknown"
        )

    except:
        pass

    try:

        url="https://api.abuseipdb.com/api/v2/check"

        headers={

            "Accept":"application/json",

            "Key":ABUSEIPDB_KEY

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

        data=r.json()

        score=data["data"]["abuseConfidenceScore"]

        result["abuse_score"]=score

        if score>75:

            result["threat"]="Critical"

        elif score>40:

            result["threat"]="Suspicious"

        else:

            result["threat"]="Safe"

    except:
        pass

    return result

