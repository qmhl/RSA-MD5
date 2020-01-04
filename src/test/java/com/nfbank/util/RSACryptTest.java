package com.nfbank.util;

import org.junit.Test;

import java.util.HashMap;

public class RSACryptTest {
    @Test
    public void testRsaCoder1() throws Exception {
        HashMap<String, String> map = RSACrypt.getKeys();
        String privateKeyStr=map.get("privateKey");
        String publicKeyStr=map.get("publicKey");
        System.out.println("初始化私钥为："+privateKeyStr);
        System.out.println("初始化共钥为："+publicKeyStr);

        System.out.println("=========================");

        //消息发送方
        String originData="周末约你看电影吧";
        System.out.println("信息原文："+originData);
        //  公钥加密
        String encryptData=RSACrypt.encrypt(RSACrypt.loadPublicKey(publicKeyStr),originData.getBytes());
        System.out.println("加密后："+encryptData);

        System.out.println("=========================");

        //消息接收方
        //  私钥解密
        String decryptData=RSACrypt.decrypt(RSACrypt.loadPrivateKey(privateKeyStr),RSACrypt.strToBase64(encryptData));
        System.out.println("解密后："+decryptData);

    }
}
