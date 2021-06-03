import sys
import time
import jwt
import datetime
import base64
import json


#we get the username
username=sys.argv[1]


#to generate the keys
# private key generation
#openssl ecparam -name prime256v1 -genkey -noout -out ecdsa_private_key.pem
# public key generation
#openssl ec -in ecdsa_private_key.pem -pubout -out ecdsa_public_key.pem

#we create a json content, convert it with jwt, and save it in a file

f = open("/home/pi/radius/notification-message/ecdsa_public_key.pem", "r")
publicEcdsaKey=f.read()
f.close()

f = open("/home/pi/radius/notification-message/ecdsa_private_key.pem", "r")
privateEcdsaKey=f.read()
f.close()


expire_at=datetime.datetime.timestamp(datetime.datetime.utcnow() + datetime.timedelta(seconds=300+7200+3600))

credential_config={"sub": "config", "exp": expire_at, "user": username}
credential_provisioning={"sub": "provisioning", "exp": expire_at, "user": username}

#we convert to jwt format
encoded_credential_config = jwt.encode(credential_config, privateEcdsaKey, algorithm="ES256")
encoded_credential_provisioning = jwt.encode(credential_provisioning, privateEcdsaKey, algorithm="ES256")
#print(encoded_credential_provisioning)

parts=encoded_credential_config.split('.')
b=str(parts[2])
encoded_credential_config=str(parts[0])+"."+str(parts[1])+"."+b


parts=encoded_credential_provisioning.split('.')
b=str(parts[2])
encoded_credential_provisioning=str(parts[0])+"."+str(parts[1])+"."+b




payload={"provision":{"url":"rpi2", "client_token": encoded_credential_provisioning, "server_cert_hashes":[{"h0":"af502fde8d07e658dcb0f4fb3ae48e80"}]},"config":{"url":"https://rpi2:8443","client_token": encoded_credential_config, "server_cert_hashes":[{"h0":"bbca86f0f644ee6be86b4e546aa4719c"}]}}
#encoded = jwt.encode(payload, privateEcdsaKey, algorithm="ES256")


"""
parts=encoded_credential_provisioning.split('.')
print(len(parts[0]+ '=' * (-len(parts[0]) % 4)))

enc=[0, 0, 0]
for i in range(3):
    with open('temp', 'w') as f:
        f.write(parts[i])
        f.close()
    with open('temp', 'rb') as f:
        enc[i]=f.read()
        f.close()


encoded=enc[0]+b'.'+enc[1]+b'.'+enc[2]
print("Encoded: ", encoded)



decoded=jwt.decode(encoded, publicEcdsaKey, algorithms=["ES256"])
print("Decoded content: ", decoded)
"""

#this is an optimized size: shorter, but does not follow the exact jwt specification
f = open('/home/pi/radius/notification-message/notification-message.txt', 'w')
f.write(json.dumps(payload))

# saving the jwt base64 message
#f = open('/home/pi/notification-message/notification-message.txt', 'wb')
#f.write(encoded)
f.close()


"""

# Comparing encodings, and for optimizing size 
ascii_encoded = encoded.decode('ascii')
temp=encoded.split(b'.')[1]
d = base64.b64decode(temp+ b'=' * (-len(temp) % 4))
# Decoding the bytes to string
utf8_encoded = d.decode("UTF-8")
signature = encoded.split(b'.')[2].decode('UTF-8')




#we save it
message=json.dumps({"payload": payload, "sign": signature})
print(message)

#this is an optimized size: shorter, but does not follow the exact jwt specification
f = open('/home/pi/notification-message/notification-message.txt', 'w')
f.write(message)
# saving the jwt base64 message
#f = open('/home/pi/notification-message/notification-message.txt', 'wb')
#f.write(encoded)
f.close()


"""

print("Notification message created")

