import urllib.parse
import socket

clean_ip = 'www.google.com'
clean_ip = socket.gethostbyname(clean_ip)
print(clean_ip)
