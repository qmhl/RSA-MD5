package com.nfbank.util;

import java.security.MessageDigest;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * @ClassName MD5Utils
 * @Description TODO
 * @Author boy
 * @Date 2019/8/30 8:29 PM
 */
public class MD5Utils {
    static char hexDigits[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    static String MD5 = "MD5";//加签方式：MD5

    /*
     * @Author boy
     * @Description 数据签名
     * @Date 2019/8/31 1:57 PM
     * @Param [data, key]
     * @return java.lang.String
     */
    public static String sign(String data, String key) throws Exception {
        //得到明文的字节数组
        byte[] btInput = (data + key).getBytes();
        // 创建一个提供信息摘要算法的对象(MD5摘要算法)
        MessageDigest messageDigest = MessageDigest.getInstance(MD5);
        // 使用指定的字节更新摘要
        messageDigest.update(btInput);
        // 得到二进制的密文
        byte[] encryptData = messageDigest.digest();
        // 把密文转换成十六进制的字符串形式
        String encryptDataStr = bytesToHex(encryptData);
        return encryptDataStr;

    }

    /*
     * @Author boy
     * @Description 验签
     * @Date 2019/8/31 1:57 PM
     * @Param [data, key, sign][明文数据,签名key,接收到的签名]
     * @return boolean
     */
    public static boolean verifySign(String data, String key, String sign) throws Exception {
        //调用加签方法，看加签后的签名是否和接收到的一致
        String encryptData = sign(data, key);
        if (encryptData.equals(sign)) {
            return true;
        } else {
            return false;
        }
    }

    /*
     * @Author boy
     * @Description 将byte数组转化为16进制字符串
     * @Date 2019/8/31 1:58 PM
     * @Param [bytes]
     * @return java.lang.String
     */
    public static String bytesToHex(byte[] bytes) {
        int k = 0;
        char[] hexChars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            byte byte0 = bytes[i];
            hexChars[k++] = hexDigits[byte0 >>> 4 & 0xf];
            hexChars[k++] = hexDigits[byte0 & 0xf];
        }
        return new String(hexChars);
    }


    /**
     * 根据传递的是map 进行MD5加签
     * @param params
     * @param signKey
     * @return
     * @throws Exception
     */
    public static String md5Sign(Map<String, String> params, String signKey) throws Exception {
        //map 进行排序 然后转为为字符串
        TreeMap<String, String> sortMap = new TreeMap<String, String>(params);
        StringBuilder sb = new StringBuilder();
        for (String key : sortMap.keySet()) {
            String val = sortMap.get(key);
            if (sb.length() > 0) {
                sb.append("&");
            }
            sb.append(key);
            sb.append("=");
            sb.append(val);
        }
        //加签的原内容a1=a1&b1=b1&c1=c1
        System.out.println("加签的原内容"+sb.toString());
        return sign(sb.toString(),signKey);
    }


    public static boolean md5VerifySign(Map<String, String> params, String signKey, String sign) throws Exception {
        //调用加签方法，看加签后的签名是否和接收到的一致

        //map 进行排序 然后转为为字符串
        TreeMap<String, String> sortMap = new TreeMap<String, String>(params);
        StringBuilder sb = new StringBuilder();
        for (String key : sortMap.keySet()) {
            String val = sortMap.get(key);
            if (sb.length() > 0) {
                sb.append("&");
            }
            sb.append(key);
            sb.append("=");
            sb.append(val);
        }
        String encryptData = sign(sb.toString(), signKey);
        if (encryptData.equals(sign)) {
            return true;
        } else {
            return false;
        }
    }


    /**
     * 获取签名
     *
     * @param time 时间戳
     * @return 签名字符串
     */
//    protected final String getSign(String sourceId, String time) {
//        String code = getAppCode(sourceId);
//        String secret = getAppHeaderSecret(sourceId);
//        String key = code + time + secret;
//        return MD5Util.md5(key);
//    }

    /**
     * 检查签名
     *
     * @param sourceId  来源id
     * @param uid       外部用户uid
     * @param phone     手机号
     * @param timestamp 时间戳
     * @param sign      签名
     * @return 是否匹配
     */
//    protected boolean checkSign(String sourceId, String uid, String phone, String timestamp, String sign) {
//        String appSecret = appSecretService.getAppSecret(sourceId);
//        if (phone == null) {
//            phone = "";
//        }
//        // 需要对时间戳进行校验是否在当前时间正负15分钟内
//        boolean checkTimeResult = checkTime(timestamp);
//        if (!checkTimeResult) {
//            return false;
//        }
//        return MD5Util.md5(sourceId + uid + phone + timestamp + appSecret).equalsIgnoreCase(sign);
//    }
//
//    private boolean checkTime(String timestamp) {
//        try {
//            if (timestamp == null || timestamp.length() < 1) {
//                return false;
//            }
//            DateFormat df = new SimpleDateFormat("yyyyMMddHHmmss");
//            Date date = df.parse(timestamp);
//            // 上下1小时内
//            return Math.abs(System.currentTimeMillis() - date.getTime()) <= 3600 * 1000;
//        } catch (Exception ex) {
//            ex.printStackTrace();
//        }
//        return true;
//    }

    public static void main(String[] args) throws Exception {
        Map<String, String> hashMap = new HashMap<>();
        String data = "你好！MD5!";
        String key = "1234567890abcdef";
        String dataSign = MD5Utils.sign(data, key);
        hashMap.put("data", data);
        hashMap.put("dataSign", dataSign);
        System.out.println("明文:" + hashMap.get("data"));
        System.out.println("签名：" + hashMap.get("dataSign"));
        System.out.println("验签结果：" + MD5Utils.verifySign(data, key, dataSign));


        //****************************************************
        System.out.println("================================");

        Map<String, String> hashMap1 = new HashMap<>();
        String signkey = "1234567890abcdef";
        hashMap1.put("a1", "a1");
        hashMap1.put("c1", "c1");
        hashMap1.put("b1", "b1");
        //  加签
        String mapdata = MD5Utils.md5Sign(hashMap1, signkey);

        System.out.println("明文:" + hashMap1.toString());
        System.out.println("签名：" + mapdata);
        System.out.println("验签结果：" + MD5Utils.md5VerifySign(hashMap1, signkey, mapdata));

//        签名的内容不一定都是按 ：a1=a1&b1=b1&c1=c1这样加签的
//        有可能是这样：
//        String key = code + time + secret;
//        return MD5Util.md5(key)
    }
}
