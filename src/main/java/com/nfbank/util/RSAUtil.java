package com.nfbank.util;

import org.apache.commons.lang3.StringUtils;

import javax.crypto.Cipher;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;


public class RSAUtil {

    private static String KEY_ALGORITHM = "RSA";
    private static String CHARSET_NAME = "UTF-8";
    private static String PUBLIC_KEY = "RSAPublicKey";
    private static String PRIVATE_KEY = "RSAPrivateKey";

    /**
     * 根据keyMap获取公钥字符串
     */
    public static String getPublicKey(Map<String, Object> keyMap) throws Exception {
        Key key = (Key) keyMap.get(PUBLIC_KEY);
        return encryptBASE64(key.getEncoded());
    }

    /**
     * 根据keyMap获取私钥字符串
     */
    public static String getPrivateKey(Map<String, Object> keyMap) throws Exception {
        Key key = (Key) keyMap.get(PRIVATE_KEY);
        return encryptBASE64(key.getEncoded());
    }

    /**
     * 初始化秘钥
     */
    public static Map<String, Object> initKey() throws NoSuchAlgorithmException {
        //获得对象 KeyPairGenerator 参数 RSA 1024个字节
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
        //公私钥对象存入map中
        Map<String, Object> keyMap = new HashMap<>(2);
        keyMap.put(PUBLIC_KEY,rsaPublicKey);
        keyMap.put(PRIVATE_KEY,rsaPrivateKey);
        return keyMap;
    }

    /**
     * 将base64编码后的公钥字符串转成PublicKey实例
     */
    public static PublicKey getPublicKey(String publicKey) throws Exception{
        byte[ ] keyBytes= Base64.getDecoder().decode(publicKey.getBytes());
        X509EncodedKeySpec keySpec=new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory=KeyFactory.getInstance(KEY_ALGORITHM);
        return keyFactory.generatePublic(keySpec);
    }

    /**
     * 将base64编码后的私钥字符串转成PrivateKey实例
     */
    public static PrivateKey getPrivateKey(String privateKey) throws Exception{
        byte[ ] keyBytes= Base64.getDecoder().decode(privateKey.getBytes());
        PKCS8EncodedKeySpec keySpec=new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory=KeyFactory.getInstance(KEY_ALGORITHM);
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * 公钥加密
     */
    public static String encrypt(String content, String public_key) throws Exception {
        PublicKey publicKey = getPublicKey(public_key);
        Cipher cipher=Cipher.getInstance(KEY_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] result = cipher.doFinal(content.getBytes(CHARSET_NAME));
        return org.apache.commons.codec.binary.Base64.encodeBase64String(result);
    }

    /**
     * 私钥解密
     */
    public static String decrypt(String content, String private_key) throws Exception {
        byte[] decodeContent = org.apache.commons.codec.binary.Base64.decodeBase64(content);
        PrivateKey privateKey = getPrivateKey(private_key);
        Cipher cipher=Cipher.getInstance(KEY_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] result = cipher.doFinal(decodeContent);
        return new String(result);
    }


    /**
     * 编码返回字符串
     */
    private static String encryptBASE64(byte[] key) throws Exception {
        return Base64.getEncoder().encodeToString(key);
    }
/**
 * ==============================================================================
 */

    /**
     * 使用RSA签名  加签：用私钥加签，对方用公钥验签（防抵赖，私钥只有自己有！）
     */
    public static String signWithRSA(Map<String, String> paramsMap, String privateKey) throws Exception {
        String content = formatSignContent(paramsMap);
        Signature signature = Signature.getInstance("SHA1WithRSA");
        signature.initSign(getPrivateKey(privateKey));
        signature.update(content.getBytes("utf-8"));
        byte[] signed = signature.sign();
        return encryptBASE64(signed);
    }

    /**
     * 使用RSA验签  加签：用私钥加签，对方用公钥验签（防抵赖，私钥只有自己有！）
     */
    public static boolean checkSignWithRSA(Map<String,String> paramsMap, String publicKey, String sign) throws Exception {
        String content = formatSignContent(paramsMap);
        Signature signature = Signature.getInstance("SHA1WithRSA");
        signature.initVerify(getPublicKey(publicKey));
        signature.update(content.getBytes("utf-8"));
        return signature.verify(Base64.getDecoder().decode(sign));
    }

    /**
     * 格式化map  升序 并且以&连接
     * 形如：
     * 格式化后的map：   akey1=value1&bey3=value3&lkey2=value2
     */
    public static String formatSignContent(Map<String, String> params) {
        Map sortedMap = sortMap(params);
        StringBuilder content = new StringBuilder();
        int index = 0;
        for (Object key : sortedMap.keySet()){
            Object value = sortedMap.get(key.toString());
            if (value != null && StringUtils.isNotBlank(value.toString())) {
                content.append(index == 0 ? "" : "&").append(key).append("=").append(value);
                index++;
            }
        }
        System.out.println("格式化后的map"+content.toString());
        return content.toString();
    }

    /**
     * map 排序  默认是升序
     * 形如：
     * 排序后的map：  {akey1=value1, bey3=value3, lkey2=value2}
     */
    public static Map sortMap(Map <String,String>map) {
        Map<String, String> sortedParams = new TreeMap<String, String>();
        sortedParams.putAll(map);
        System.out.println("排序后的map"+sortedParams.toString());

        return sortedParams;
    }


    public static void main(String[] args) throws Exception {
        Map<String, Object> keyMap = initKey();
        String publicKey = getPublicKey(keyMap);
        String privateKey = getPrivateKey(keyMap);
        String content = "hello world";
        String encryptContent = encrypt(content,publicKey);
        String decryptContent = decrypt(encryptContent,privateKey);
        System.out.println("生成的公钥字符串：" + publicKey);
        System.out.println("生成的私钥字符串：" + privateKey);
        System.out.println("加密后的数据：" + encryptContent);
        System.out.println("解密后的数据：" + decryptContent);

        Map<String,String> map = new HashMap<>();
        map.put("akey1","value1");
        map.put("lkey2","value2");
        map.put("bey3","value3");

        String sign = signWithRSA(map,privateKey);
        boolean check = checkSignWithRSA(map,publicKey,sign);
        System.out.println("签名结果，sign:"+sign);
        System.out.println("验签结果，result:"+check);
    }
}
