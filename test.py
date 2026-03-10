import ipaddress
from maltiverse import Maltiverse
import socket

# instantiate object to interact with Maltiverse API
api = Maltiverse(auth_token="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjIzNjcwMzM4NzYsImlhdCI6MTczNjMxMzg3Niwic3ViIjoyMDc1MiwidXNlcm5hbWUiOiJrYWxlZW0ubW1kIiwiYWRtaW4iOmZhbHNlLCJ0ZWFtX2lkIjpudWxsLCJ0ZWFtX25hbWUiOm51bGwsInRlYW1fbGVhZGVyIjpmYWxzZSwidGVhbV9yZXNlYXJjaGVyIjpmYWxzZSwidGVhbV9pbmRleCI6bnVsbCwiYXBpX2xpbWl0IjoxMDB9.R2lGorrRds3LTmyhA9dzANDFCLAUjUG0muzQYoTwmqw")

clean_ip = 'www.google.com'
clean_ip = socket.gethostbyname(clean_ip)
print(clean_ip)

try:
    ipaddress.ip_address(clean_ip)
except ValueError:
    print(f" - {clean_ip} is not a valid IP address. Please try again...\n")
    

# query Maltiverse API for data about the result
result = api.ip_get(clean_ip)

# check if the 'classification' key is present
try:
    # print the 'classification' of the IP address
    print(f"\n=> The IP address {clean_ip} has been identified as {result['classification']} by Maltiverse\n")
except KeyError:
    # no classification available from Maltiverse
    print(f"\n - The IP address {clean_ip} cannot classified by Maltiverse\n")
