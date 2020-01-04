package com.zhangqi.util;

import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

public class RSAUtilTest {
    @Test
    public void testRsaCoder1() throws Exception {
        Map<String, Object> keyMap = RSAUtil.initKey();
        String publicKey = RSAUtil.getPublicKey(keyMap);
        String privateKey = RSAUtil.getPrivateKey(keyMap);
        String content = "hello world";
        String encryptContent = RSAUtil.encrypt(content,publicKey);
        String decryptContent = RSAUtil.decrypt(encryptContent,privateKey);
        System.out.println("生成的公钥字符串：" + publicKey);
        System.out.println("生成的私钥字符串：" + privateKey);
        System.out.println("加密后的数据：" + encryptContent);
        System.out.println("解密后的数据：" + decryptContent);

        Map<String,String> map = new HashMap<>();
        map.put("akey1","value1");
        map.put("lkey2","value2");
        map.put("bey3","value3");

        String sign = RSAUtil.signWithRSA(map,privateKey);
        boolean check = RSAUtil.checkSignWithRSA(map,publicKey,sign);
        System.out.println("签名结果，sign:"+sign);
        System.out.println("验签结果，result:"+check);
    }
}
