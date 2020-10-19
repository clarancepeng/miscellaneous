package org.algo.utils;

import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.util.Base64Utils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSAUtils {

    /**
     * Algorithm used by AES keys and ciphers.
     */
    public static final String AES_ALGORITHM = "AES";
    /**
     * Number of bits for AES 128 bit key.
     */
    public static final int AES_128 = 128;
    /**
     * Number of bits for AES 256 bit key.
     */
    public static final int AES_256 = 256;

    /**
     * Algorithm used by DSA keys.
     */
    public static final String DSA_ALGORITHM = "DSA";
    /**
     * Algorithm used for signature with DSA key.
     */
    public static final String DSA_SIGNATURE_ALGORITHM = "SHA1withDSA";
    /**
     * Number of bits for RSA 1024 bit key.
     */
    public static final int RSA_1024 = 1024;

    /**
     * Algorithm used by RSA keys and ciphers.
     */
    public static final String RSA_ALGORITHM = "RSA";
    /**
     * Algorithm used for signature with RSA key.
     */
    public static final String RSA_SIGNATURE_ALGORITHM = "SHA1withRSA";
    /**
     * Number of bits for RSA 2048 bit key.
     */
    public static final int RSA_2048 = 2048;
    /**
     * Number of bits for RSA 4096 bit key.
     */
    public static final int RSA_4096 = 4096;

    public static final String publicKeyString =
                "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCwPCaPFGyrfhVz0z0Ok6NL23Gg" +
                        "MievInxtOrjC6soFu6OPLj9fexK3BdJTMQN7a7LipJfq5M6i/I4O2RZaiaDqW3uK" +
                        "8sJiMhH5EmrZf/l3WyCXANf+3XNv188qUOc7c4ajAy2YYcWN3P16VbUcF16qEvBJ" +
                        "ma1rE+KNSV1tTNqdqQIDAQAB";

    public static final String privateKeyString =
            "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALA8Jo8UbKt+FXPT" +
                    "PQ6To0vbcaAyJ68ifG06uMLqygW7o48uP197ErcF0lMxA3trsuKkl+rkzqL8jg7Z" +
                    "FlqJoOpbe4rywmIyEfkSatl/+XdbIJcA1/7dc2/XzypQ5ztzhqMDLZhhxY3c/XpV" +
                    "tRwXXqoS8EmZrWsT4o1JXW1M2p2pAgMBAAECgYBpcSO02YiHNqHJMerHDOhX24zp" +
                    "RvjdXSnLBKZE4MtMkM60PPxnuTAiVxZW9e1aa76UwduvC4TimW65TYOFWfDvJ6Q7" +
                    "9vk6bYgxZd9/dN8uPBKnlE0xKa11XYIfZHlfAkcr8JxNXUazdwRmJKrl3KWtbL55" +
                    "qd5QjTZSuI+ZJa75gQJBAOrzM1B33/5dsYUHMwR5t0dw9gBQAWB8+zURk9/S5Kj3" +
                    "Pp9WNmaUXbuCSTeIPyBBjaPGnvyuCbZ3G59XPqzhyTkCQQDABkP2HOBXjmS48zCf" +
                    "WdZEPcaaAuKJxk/mAouX8LcAa9/JDjEnvNIa6gX9Aj8QLJcgeNabxTMa5hZrLrv6" +
                    "SKfxAkBb85ykpJXMpnygdKXZ3Y0Gb8ZHbwhq698g8OUv1wjYvBMNJx+ZW/2nMiFX" +
                    "k4IpLJ6zdzun5rE0cT8lSG7mGGO5AkEAkYcuEmOoEjM0WobUHrBzFpzK2wW8sjW9" +
                    "b9AWAzzHNGaM308GKduMUCF0EF+Xc6aXkmCCJOO663PdIbX1eKV/wQJAE78vU3nM" +
                    "+LAWDuvIpxJBD50TYAsMp3sAOOsolet8wv71/MtCWoFVBhmM/1qdYURp4f4jSC1C" +
                    "6WvjdJ7Z8mbVxw==";

    public static String encrypt(String str, String publicKey) throws Exception {
        //base64编码的公钥
        byte[] decoded = Base64.decodeBase64(publicKey);
        RSAPublicKey pubKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));
        //RSA加密
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        String outStr = Base64.encodeBase64String(cipher.doFinal(str.getBytes("UTF-8")));
        return outStr;
    }

    public static void signBody(byte[] headerData, byte[] bodyContent) throws Exception {
        byte[] decoded = Base64.decodeBase64(privateKeyString);
        PrivateKey privateKey = readPrivateKey(decoded); //(RSAPrivateKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));
        //RSA加密
        Signature signature = Signature.getInstance(RSA_SIGNATURE_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(bodyContent);

        //String outStr = Base64.encodeBase64String(cipher.doFinal(content.getBytes("UTF-8")));
        byte[] outStr = signature.sign();

        for (int i = 0; i < outStr.length; i++) {
            headerData[14 + i] = outStr[i];
        }
    }

    public static PrivateKey readPrivateKey(final byte[] bytes)
            throws IOException, NoSuchAlgorithmException {
        byte[] data = bytes;
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(data);

        try {
            return KeyFactory.getInstance(DSA_ALGORITHM).generatePrivate(spec);
        } catch (InvalidKeySpecException e) {
            try {
                return KeyFactory.getInstance(RSA_ALGORITHM).generatePrivate(
                        spec);
            } catch (InvalidKeySpecException e2) {
                // ignore
            }
        }

        return null;
    }

    public static PublicKey readPublicKey(final byte[] bytes)
            throws IOException, NoSuchAlgorithmException {
        byte[] data = bytes;
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(data);
        try {
            return KeyFactory.getInstance(DSA_ALGORITHM).generatePublic(spec);
        } catch (InvalidKeySpecException e) {
            try {
                return KeyFactory.getInstance(RSA_ALGORITHM).generatePublic(
                        spec);
            } catch (InvalidKeySpecException e2) {
                // ignore
            }
        }
        return null;
    }


    /**
     * 获取公钥对象
     *
     * @param publicKeyBase64
     * @return
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     */
    public static PublicKey getPublicKey(String publicKeyBase64)
            throws InvalidKeySpecException, NoSuchAlgorithmException {

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicpkcs8KeySpec =
                new X509EncodedKeySpec(Base64.decodeBase64(publicKeyBase64));
        PublicKey publicKey = keyFactory.generatePublic(publicpkcs8KeySpec);
        return publicKey;
    }

    /**
     * 获取私钥对象
     *
     * @param privateKeyBase64
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PrivateKey getPrivateKey(String privateKeyBase64)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privatekcs8KeySpec =
                new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKeyBase64));
        PrivateKey privateKey = keyFactory.generatePrivate(privatekcs8KeySpec);
        return privateKey;
    }

    /**
     * 使用工钥加密
     *
     * @param content         待加密内容
     * @param publicKeyBase64 公钥 base64 编码
     * @return 经过 base64 编码后的字符串
     */
    public static String encipher(String content, String publicKeyBase64) {
        return encipher(content, publicKeyBase64, RSA_1024 / 8 - 11);
    }

    /**
     * 使用公司钥加密（分段加密）
     *
     * @param content         待加密内容
     * @param publicKeyBase64 公钥 base64 编码
     * @param segmentSize     分段大小,一般小于 keySize/8（段小于等于0时，将不使用分段加密）
     * @return 经过 base64 编码后的字符串
     */
    public static String encipher(String content, String publicKeyBase64, int segmentSize) {
        try {
            PublicKey publicKey = getPublicKey(publicKeyBase64);
            return encipher(content, publicKey, segmentSize);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 分段加密
     *
     * @param ciphertext  密文
     * @param key         加密秘钥
     * @param segmentSize 分段大小，<=0 不分段
     * @return
     */
    public static String encipher(String ciphertext, java.security.Key key, int segmentSize) {
        try {
            // 用公钥加密
            byte[] srcBytes = ciphertext.getBytes();

            // Cipher负责完成加密或解密工作，基于RSA
            Cipher cipher = Cipher.getInstance("RSA");
            // 根据公钥，对Cipher对象进行初始化
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] resultBytes = null;

            if (segmentSize > 0)
                resultBytes = cipherDoFinal(cipher, srcBytes, segmentSize); //分段加密
            else
                resultBytes = cipher.doFinal(srcBytes);
            String base64Str = Base64Utils.encodeToString(resultBytes);
            return base64Str;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 分段大小
     *
     * @param cipher
     * @param srcBytes
     * @param segmentSize
     * @return
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws IOException
     */
    public static byte[] cipherDoFinal(Cipher cipher, byte[] srcBytes, int segmentSize)
            throws IllegalBlockSizeException, BadPaddingException, IOException {
        if (segmentSize <= 0)
            throw new RuntimeException("分段大小必须大于0");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int count = srcBytes.length / segmentSize;
        for (int i = 0; i < count; i++) {
            out.write(cipher.doFinal(srcBytes, i * count, segmentSize));
        }
        byte[] data = out.toByteArray();
        out.close();
        return data;
    }

    /**
     * 使用私钥解密
     *
     * @param contentBase64    待加密内容,base64 编码
     * @param privateKeyBase64 私钥 base64 编码
     * @return
     * @segmentSize 分段大小
     */
    public static String decipher(String contentBase64, String privateKeyBase64) {
        return new String(decipher(contentBase64, privateKeyBase64, 128));
    }

    public static byte[] decipherBytes(byte[] content, String privateKeyBase64) {
        return decipher(content, privateKeyBase64, 128);
    }

    /**
     * 使用私钥解密（分段解密）
     *
     * @param contentBase64    待加密内容,base64 编码
     * @param privateKeyBase64 私钥 base64 编码
     * @return
     * @segmentSize 分段大小
     */
    public static byte[] decipher(String contentBase64, String privateKeyBase64, int segmentSize) {
        try {
            PrivateKey privateKey = getPrivateKey(privateKeyBase64);
            return decipher(contentBase64, privateKey, segmentSize);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] decipher(byte[] content, String privateKeyBase64, int segmentSize) {
        try {
            PrivateKey privateKey = getPrivateKey(privateKeyBase64);
            return decipher(content, privateKey, segmentSize);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 分段解密
     *
     * @param contentBase64 密文
     * @param key           解密秘钥
     * @param segmentSize   分段大小（小于等于0不分段）
     * @return
     */
    public static byte[] decipher(String contentBase64, java.security.Key key, int segmentSize) {
        try {
            // 用私钥解密
            byte[] srcBytes = Base64Utils.decodeFromString(contentBase64);
            // Cipher负责完成加密或解密工作，基于RSA
            Cipher deCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            // 根据公钥，对Cipher对象进行初始化
            deCipher.init(Cipher.DECRYPT_MODE, key);
            //byte[] decBytes;//deCipher.doFinal(srcBytes);
            if (segmentSize > 0) {
                return cipherDoFinal(deCipher, srcBytes, segmentSize); //分段加密
            } else {
                return deCipher.doFinal(srcBytes);
            }
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] decipher(byte[] content, java.security.Key key, int segmentSize) {
        try {
            // Cipher负责完成加密或解密工作，基于RSA
            Cipher deCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            // 根据公钥，对Cipher对象进行初始化
            deCipher.init(Cipher.DECRYPT_MODE, key);
            //byte[] decBytes;//deCipher.doFinal(srcBytes);
            if (segmentSize > 0) {
                return cipherDoFinal(deCipher, content, segmentSize); //分段加密
            } else {
                return deCipher.doFinal(content);
            }
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }


    public static byte[] decrypt(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        int count = data.length / 128;
        ByteArrayOutputStream out = new ByteArrayOutputStream(1024);
        for (int i = 0; i < count; i++) {
            out.write(cipher.doFinal(data, i * 128, 128));
        }
        return out.toByteArray();
    }

    public static byte[] decrypt(byte[] content, String privateKeyBase64) {
        try {
            PrivateKey privateKey = getPrivateKey(privateKeyBase64);
            return decrypt(content, privateKey);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) throws Exception {
        String rsaString = RSAUtils.encrypt("123456", publicKeyString);
        System.out.println("RSA encode string = " + rsaString);
        byte[] ret = RSAUtils.decrypt(Base64.decodeBase64(rsaString), privateKeyString);
        System.out.println("RSA decode string = " + new String(ret));

    }
}
