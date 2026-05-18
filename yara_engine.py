import yara

rules=yara.compile(

filepath="rules/malware_rules.yar"

)

def yara_scan(path):

    matches=rules.match(path)

    return matches
