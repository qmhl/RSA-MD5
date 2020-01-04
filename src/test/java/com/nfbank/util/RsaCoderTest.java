package com.nfbank.util;

import org.junit.Test;

public class RsaCoderTest {
    /**
     * 测试私钥
     */
    public static String priKey = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAK6P7ZO9nFl5M1Ybcx4F4FRtRZA2R60KEGlzETQ7xYwUA2McppZxtJmxpQePdun8PyQxznTwexDwnlXbJ4Cz9k9Ip+ZL7J8zeiPaRDNjRori3iYSYJ51UANDbl5ty2MK6bznyMVyxcDiKFgRc+V5BPS+F5pH6NDJb6S5bDrszk6/AgMBAAECgYB/4A2xAeCsJr41oOwmnTVlg5rG9wxwtYOqS9HZisO/RtXoYA+k++zJ/jmfnTgGVnPGxvmv7o6orSvAR0fb33laCxccTApqztL0aVRk0IiDH4DK8dV7O2IWFUawfjiQKSCDgbWI7zcdoOgUz15OxuhBUXYlB10fHIVcGxUbFI08aQJBAN2NK/R1hfflW1I682uemmBoSuYwJ93nPBhHoWXTlyaYcWme4UJXG5A4BW3hwC2Q7DacmHy1Hqix/8XCV4BV85UCQQDJtFsOsOmbvumvsvYWm8SB0ilqerc0PKJr6Ixy3sqF6mjTJnAbCeMH8ue5J9F0DFLU2wNXvtXO9iyljJS8faQDAkEAu8Qkh4d+5ezNa7CokwIVRjW9nL8dWpTaOp2irQEZrk0ueVx8/tOCecTw3QKh9DxJ5bLsDW0XMdPBuOIPdKXjzQJAVg2UK5hekgvJNyRqyQp7s8ct1De2oZqc0NzNztQuIyP2xN7JRT/alDGVmvDZ82CulhE6Q90u6rUsJxTq/9+6cQJBAKKKvOm7m5oexiHEhVQw3QQ0M8mmHK7j4li8AQkheSWgGVtR7Kz905H1w4qFQGnWsmBga8qVFSGYn96jtIrCs+s=";
    /**
     * 测试公钥
     */
    public static String pubKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCuj+2TvZxZeTNWG3MeBeBUbUWQNketChBpcxE0O8WMFANjHKaWcbSZsaUHj3bp/D8kMc508HsQ8J5V2yeAs/ZPSKfmS+yfM3oj2kQzY0aK4t4mEmCedVADQ25ebctjCum858jFcsXA4ihYEXPleQT0vheaR+jQyW+kuWw67M5OvwIDAQAB";

    @Test
    public void testRsaCoder1() throws Exception {
        RsaCoder rsaCoder = new RsaCoder(pubKey, priKey);
        String str = "{\"sourceId\":\"GUOMEI\",\"name\":\"马\",\"idNo\":\"210727199903228899\"}";
        // 根据私钥加密

        String s = rsaCoder.encryptByPrivateKey(str);
        System.out.println(s);
        // 根据公钥解密

        String s1 = rsaCoder.decryptByPublicKey(s);
        System.out.println(s1);
    }

    /**
     * json串加密解密
     *
     * @throws Exception
     */
    @Test
    public void testRsaCoder2() throws Exception {
        String jsonStr = "{\"certId\":\"110226199009141610\",\"name\":\"%E9%99%88%E6%B5%A9\",\"mobile\":\"13810127680\"}";
        //根据pubKey, priKey  字符串生成公钥 私钥  初始化
        RsaCoder rsaEncoder = new RsaCoder(pubKey, priKey);
        // 根据公钥加密
        String s = rsaEncoder.encryptByPublicKey(jsonStr);
        System.out.println(s);

        RsaCoder rsaDecoder = new RsaCoder(pubKey, priKey);
        // 根据私钥解密
        String s1 = rsaDecoder.decryptByPrivateKey(s);
        System.out.println(s1);
    }
}