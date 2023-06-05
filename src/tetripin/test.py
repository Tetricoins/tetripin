
import os
import requests

# max size : 1048576
path = "/home/user/Bureau/(Image PNG, 200 × 200 pixels).png"
f = open(path, 'rb')
response = requests.post(
    "http://api.qrserver.com/v1/read-qr-code/",
    files={"file": f},
    data={'MAX_FILE_SIZE': os.path.getsize(path)}
)
