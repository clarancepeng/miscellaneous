1) 生成长度为1024的私钥
openssl genrsa -out rsa_private_key.pem 1024

2）根据私钥生成对应的公钥：
openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem

3) 私钥转化成pkcs8格式, 将转化好的私钥写到rsa_private_key_pkcs8.pem文件里
openssl pkcs8 -topk8 -inform PEM -in rsa_private_key.pem -outform PEM -nocrypt > rsa_private_key_pkcs8.pem

