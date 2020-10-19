一. 生成长度为1024的私钥

openssl genrsa -out rsa_private_key.pem 1024

二. 根据私钥生成对应的公钥：

openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem

三. 私钥转化成pkcs8格式, 将转化好的私钥写到rsa_private_key_pkcs8.pem文件里

openssl pkcs8 -topk8 -inform PEM -in rsa_private_key.pem -outform PEM -nocrypt > rsa_private_key_pkcs8.pem



----------------------------------------------------------------------------------------------------


1. root># openssl genrsa -out rootkey.pem 2048

Generating RSA private key, 2048 bit long modulus
.......+++
..................+++
e is 65537 (0x10001)

2. root># openssl req -x509 -new -key rootkey.pem -out root.crt

You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:cn
State or Province Name (full name) [Some-State]:Guangdong
Locality Name (eg, city) []:Shenzhen
Organization Name (eg, company) [Internet Widgits Pty Ltd]:hstong.com
Organizational Unit Name (eg, section) []:hstong
Common Name (e.g. server FQDN or YOUR name) []:fixgateway
Email Address []:fixgateway@hstong.com

3. root># openssl genrsa -out clientkey.pem 2048

Generating RSA private key, 2048 bit long modulus
...+++
..............................................................................................+++
e is 65537 (0x10001)

4. root># openssl req -new -key clientkey.pem -out client.csr

You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:cn
State or Province Name (full name) [Some-State]:Guangdong
Locality Name (eg, city) []:Shenzhen
Organization Name (eg, company) [Internet Widgits Pty Ltd]:hstong.com
Organizational Unit Name (eg, section) []:hstong
Common Name (e.g. server FQDN or YOUR name) []:fixgateway
Email Address []:fixgateway@hstong.com

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:password
An optional company name []:hstong

5. root># openssl x509 -req -in client.csr -CA root.crt -CAkey rootkey.pem -CAcreateserial -days 3650 -out client.crt

Signature ok
subject=/C=cn/ST=Guangdong/L=Shenzhen/O=hstong.com/OU=hstong/CN=fixgateway/emailAddress=fixgateway@hstong.com
Getting CA Private Key

6. root># openssl genrsa -out serverkey.pem 2048

Generating RSA private key, 2048 bit long modulus
....+++
........................................................................+++
e is 65537 (0x10001)

7. root># openssl req -new -key serverkey.pem -out server.csr

You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:cn
State or Province Name (full name) [Some-State]:Guangdong
Locality Name (eg, city) []:Shenzhen
Organization Name (eg, company) [Internet Widgits Pty Ltd]:hstong.com
Organizational Unit Name (eg, section) []:hstong
Common Name (e.g. server FQDN or YOUR name) []:fixgateway
Email Address []:fixgateway@hstong.com

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:password
An optional company name []:hstong

8. root># openssl x509 -req -in server.csr -CA root.crt -CAkey rootkey.pem -CAcreateserial -days 3650 -out server.crt

Signature ok
subject=/C=cn/ST=Guangdong/L=Shenzhen/O=hstong.com/OU=hstong/CN=fixgateway/emailAddress=fixgateway@hstong.com
Getting CA Private Key

9. root># openssl pkcs12 -export -in client.crt -inkey clientkey.pem -out client.pkcs12

Enter Export Password:
Verifying - Enter Export Password:

10. root># openssl pkcs12 -export -in server.crt -inkey serverkey.pem -out server.pkcs12

Enter Export Password:
Verifying - Enter Export Password:

11. root># keytool -importkeystore -srckeystore client.pkcs12 -destkeystore client.jks -srcstoretype pkcs12

Enter destination keystore password:  
Re-enter new password: 
Enter source keystore password:  
Entry for alias 1 successfully imported.
Import command completed:  1 entries successfully imported, 0 entries failed or cancelled

12. root># keytool -importkeystore -srckeystore server.pkcs12 -destkeystore server.jks -srcstoretype pkcs12

Enter destination keystore password:  
Re-enter new password: 
Enter source keystore password:  
Entry for alias 1 successfully imported.
Import command completed:  1 entries successfully imported, 0 entries failed or cancelled

13. root># keytool -importcert -alias ca -file root.crt -keystore clienttrust.jks

Enter keystore password:  
Re-enter new password: 
Owner: EMAILADDRESS=fixgateway@hstong.com, CN=fixgateway, OU=hstong, O=hstong.com, L=Shenzhen, ST=Guangdong, C=cn
Issuer: EMAILADDRESS=fixgateway@hstong.com, CN=fixgateway, OU=hstong, O=hstong.com, L=Shenzhen, ST=Guangdong, C=cn
Serial number: 991980f8847243ad
Valid from: Sun Oct 13 22:15:32 EDT 2019 until: Tue Nov 12 21:15:32 EST 2019
Certificate fingerprints:
	 MD5:  D4:83:EE:22:9E:86:0D:8A:DA:AA:05:3D:3D:54:CB:BE
	 SHA1: 02:72:97:42:21:AA:85:96:FA:39:0B:7C:5A:FD:8F:E5:69:AE:5B:36
	 SHA256: 8F:4D:50:13:90:D6:FB:C9:19:74:C5:18:38:41:5E:66:11:C3:FF:BC:B9:1A:C5:46:6B:A8:D4:43:C6:90:EF:A4
	 Signature algorithm name: SHA256withRSA
	 Version: 3

Extensions: 

#1: ObjectId: 2.5.29.35 Criticality=false
AuthorityKeyIdentifier [
KeyIdentifier [
0000: C0 7C 08 AB 64 1A 42 BA   71 F3 30 8E A9 5C 46 75  ....d.B.q.0..\Fu
0010: E4 AD E2 E5                                        ....
]
]

#2: ObjectId: 2.5.29.19 Criticality=false
BasicConstraints:[
  CA:true
  PathLen:2147483647
]

#3: ObjectId: 2.5.29.14 Criticality=false
SubjectKeyIdentifier [
KeyIdentifier [
0000: C0 7C 08 AB 64 1A 42 BA   71 F3 30 8E A9 5C 46 75  ....d.B.q.0..\Fu
0010: E4 AD E2 E5                                        ....
]
]

Trust this certificate? [no]:  yes
Certificate was added to keystore


14. root># keytool -importcert -alias clientcert -file client.crt -keystore clienttrust.jks

Enter keystore password:  
Certificate was added to keystore

15. root># keytool -importcert -alias ca -file root.crt -keystore servertrust.jks

Enter keystore password:  
Re-enter new password: 
Owner: EMAILADDRESS=fixgateway@hstong.com, CN=fixgateway, OU=hstong, O=hstong.com, L=Shenzhen, ST=Guangdong, C=cn
Issuer: EMAILADDRESS=fixgateway@hstong.com, CN=fixgateway, OU=hstong, O=hstong.com, L=Shenzhen, ST=Guangdong, C=cn
Serial number: 991980f8847243ad
Valid from: Sun Oct 13 22:15:32 EDT 2019 until: Tue Nov 12 21:15:32 EST 2019
Certificate fingerprints:
	 MD5:  D4:83:EE:22:9E:86:0D:8A:DA:AA:05:3D:3D:54:CB:BE
	 SHA1: 02:72:97:42:21:AA:85:96:FA:39:0B:7C:5A:FD:8F:E5:69:AE:5B:36
	 SHA256: 8F:4D:50:13:90:D6:FB:C9:19:74:C5:18:38:41:5E:66:11:C3:FF:BC:B9:1A:C5:46:6B:A8:D4:43:C6:90:EF:A4
	 Signature algorithm name: SHA256withRSA
	 Version: 3

Extensions: 

#1: ObjectId: 2.5.29.35 Criticality=false
AuthorityKeyIdentifier [
KeyIdentifier [
0000: C0 7C 08 AB 64 1A 42 BA   71 F3 30 8E A9 5C 46 75  ....d.B.q.0..\Fu
0010: E4 AD E2 E5                                        ....
]
]

#2: ObjectId: 2.5.29.19 Criticality=false
BasicConstraints:[
  CA:true
  PathLen:2147483647
]

#3: ObjectId: 2.5.29.14 Criticality=false
SubjectKeyIdentifier [
KeyIdentifier [
0000: C0 7C 08 AB 64 1A 42 BA   71 F3 30 8E A9 5C 46 75  ....d.B.q.0..\Fu
0010: E4 AD E2 E5                                        ....
]
]

Trust this certificate? [no]:  yes
Certificate was added to keystore

16. root># keytool -importcert -alias servercert -file server.crt -keystore servertrust.jks

Enter keystore password:  
Certificate was added to keystore

