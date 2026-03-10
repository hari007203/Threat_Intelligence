from maltiverse import Maltiverse

api = Maltiverse(auth_token='eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjIzNjcwMzM4NzYsImlhdCI6MTczNjMxMzg3Niwic3ViIjoyMDc1MiwidXNlcm5hbWUiOiJrYWxlZW0ubW1kIiwiYWRtaW4iOmZhbHNlLCJ0ZWFtX2lkIjpudWxsLCJ0ZWFtX25hbWUiOm51bGwsInRlYW1fbGVhZGVyIjpmYWxzZSwidGVhbV9yZXNlYXJjaGVyIjpmYWxzZSwidGVhbV9pbmRleCI6bnVsbCwiYXBpX2xpbWl0IjoxMDB9.R2lGorrRds3LTmyhA9dzANDFCLAUjUG0muzQYoTwmqw')

def isMalicious(result):
    classification = result.get('classification', 'neutral')
    if classification in ['whitelist', 'neutral']:
        return False
    if classification == 'malicious':
        return True
    is_phishing = result.get('is_phishing') or result.get('is_storing_phishing')
    tags = result.get('tag', [])
    dangerous_tags = set(['phishing', 'malware', 'trojan', 'ransomware', 'botnet', 'scam'])
    has_dangerous_tag = bool(dangerous_tags.intersection(set(tags))) if tags else False
    blacklist_malicious = False
    for bl in result.get('blacklist', []):
        labels = bl.get('labels', [])
        if 'malicious-activity' in labels or 'compromised' in labels:
            blacklist_malicious = True
            break
    if classification == 'suspicious' and (is_phishing or has_dangerous_tag or blacklist_malicious):
        return True
    if is_phishing or has_dangerous_tag:
        return True
    return False

# These are known phishing hostnames from OpenPhish and other feeds that Maltiverse indexes
domains = [
    'vzr8ewbr91ro62ntalby90mtqz81c9zv.ocalam.com',
    'usmatamesklogi9.godaddysites.com',
    'sberbank-online.com',
    'paypal-account-limit.securityupdate.id',
    'account.wellsfargo-alerts.com',
    'rn5dg4pnbxhf93mtalby7ymu.ocalam.com',
    'kd8kbqwr91ro47ntalby90mtqm72c4yp.ocalam.com',
    'security-bankofamerica-myaccount.com',
    'update-your-paypal.com',
    'mx4kbqzr81ro52ntalby801tqm72c4yp.ocalam.com',
    'phishing-test.acme.godaddysites.com',
    'x0balqwj91ro47mtaly90mtqm72c4yp.ocalam.com',
    'fake-amazon-delivery.godaddysites.com',
    'wallet-metamask-secure.godaddysites.com',
    'apple-id-verify.godaddysites.com',
]

confirmed_malicious = []
print('=== Testing domains ===')
for d in domains:
    try:
        r = api.hostname_get(d)
        verdict = 'MALICIOUS' if isMalicious(r) else 'SAFE'
        print(d, '->', verdict, '| class:', r.get('classification'), '| phishing:', r.get('is_phishing'), '| tags:', r.get('tag'))
        if isMalicious(r):
            confirmed_malicious.append((d, r.get('classification'), r.get('tag', []), r.get('is_phishing')))
    except Exception as e:
        print(d, '-> ERROR:', e)

print('\n=== CONFIRMED MALICIOUS ({}) ==='.format(len(confirmed_malicious)))
for d, cls, tags, phish in confirmed_malicious:
    print('  www.' + d, '| class:', cls, '| is_phishing:', phish, '| tags:', tags)
