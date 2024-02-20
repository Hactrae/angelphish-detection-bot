import socket
import urllib.parse
from urllib.parse import urlparse

url = input("Enter a url: ")
urlparse(url).hostname

# Code to extact webiste data to turn into data to train bot
# 1 if the data relates to not phishy activity
# 0 if the data relates to suspicious activity
# -1 if the data relates to phishy activity

webData = []

# 1 IP adress in url 
def is_ip_address_legit(url):
    return socket.gethostbyname(urlparse(url).hostname) != url


# 2 Long url
size = len(url)
print(size)

if (size < 54):
    webData.append(1)
elif (size >= 54 or size < 72):
    webData.append(0)
else:
    webData.append(-1)

# 3 url contains "@"
if "@" in url:
    webData.append(-1)
else:
    webData.append(1)

# 4 url has a fake prefix or suffix
def part_4_is_suspicious(url):
    parse = urlparse(url).hostname
    if len(parse) == 0:
        # malformed url, maybe should throw error in here instead
        return True
    for part in parse.split("."):
        # print(part)
        if part.startswith("_") or part.endswith("_"):
            return -1
    return 0

print(part_4_is_suspicious(url))

# 5 sub domains
num = sum((int(x == ".") for x in url))

if (num < 3):
    webData.append(1)
elif (num == 3):
    webData.append(0)
else:
    webData.append(-1)

# 6 Fake HTTPS protocols 

print(webData)