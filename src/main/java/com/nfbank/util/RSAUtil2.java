package com.nfbank.util;

import org.springframework.util.Base64Utils;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;

public class RSAUtil2 {
	/**
	 * 加密算法RSA
	 */
	public static final String KEY_ALGORITHM = "RSA";

	/**
	 * 签名算法 SHA1WithRSA
	 */
	public static final String SIGNATURE_ALGORITHM_SHA1 = "SHA1WithRSA";
	private static final String encoding = "UTF-8";

	/**
	 * 验证签名
	 *
	 * @param data  字节数组
	 * @param publicKey
	 * @param sign
	 * @return
	 * @throws Exception
	 */
	public static boolean verify(byte[] data, String publicKey, String sign) throws Exception {
		byte[] keyBytes = Base64Utils.decode(publicKey.getBytes(encoding));
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		PublicKey publicK = keyFactory.generatePublic(keySpec);
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM_SHA1);
		signature.initVerify(publicK);
		signature.update(data);
		return signature.verify(Base64Utils.decode(sign.getBytes(encoding)));
	}

	/**
	 * 根据字节数组 生成签名 （string是根据key排序后的 key=value1&key2=value2的拼接）
	 * @param data
	 * @param privateKey
	 * @return
	 * @throws Exception
	 */
	public static String sign(byte[] data, String privateKey) throws Exception {
		byte[] keyBytes = Base64Utils.decode(privateKey.getBytes(encoding));
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		PrivateKey privateK = keyFactory.generatePrivate(pkcs8KeySpec);
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM_SHA1);
		signature.initSign(privateK);
		signature.update(data);
		return new String(Base64Utils.encode(signature.sign()));
	}

	/**
	 * 根据 map 集合生成签名
	 * @param params
	 * @param privateKey
	 * @return
	 * @throws Exception
	 */
	public static String sign(Map<String, String> params, String privateKey) throws Exception {
		//  对map进行排序
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
		byte[] data = sb.toString().getBytes("utf-8");
		byte[] keyBytes = Base64Utils.decode(privateKey.getBytes(encoding));
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		PrivateKey privateK = keyFactory.generatePrivate(pkcs8KeySpec);
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM_SHA1);
		signature.initSign(privateK);
		signature.update(data);
		return new String(Base64Utils.encode(signature.sign()));
	}

	/**
	 * 根据map集合   验证签名
	 * @param params   map集合
	 * @param publicKey
	 * @param sign
	 * @return
	 * @throws Exception
	 */
	public static boolean verify(Map<String, String> params, String publicKey, String sign) throws Exception {
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
		byte[] data = sb.toString().getBytes("utf-8");
		byte[] keyBytes = Base64Utils.decode(publicKey.getBytes(encoding));
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		PublicKey publicK = keyFactory.generatePublic(keySpec);
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM_SHA1);
		signature.initVerify(publicK);
		signature.update(data);
		return signature.verify(Base64Utils.decode(sign.getBytes(encoding)));
	}



//	public Map<String, String> fetchUserInfo(String sourceId, String outerUserId) throws Exception {
//		String requestId = UUID.randomUUID().toString().toUpperCase();
//
//		String sign = RSAUtil.sign(("userId=" + outerUserId).getBytes("utf-8"), jfPriKey);
//		Map<String, Object> params = new HashMap<String, Object>();
//		params.put("sign", sign);
//		params.put("userId", outerUserId);
//		params.put("request_id", requestId);
//		//  生成签名去访问第三方
//		String result = Jsoup.connect(url).method(Method.POST).header("Content-Type", "application/json; charset=utf-8")
//				.timeout(60000).requestBody(JSONObject.toJSONString(params, true)).ignoreContentType(true)
//				.ignoreHttpErrors(true).execute().body();
//		if (logger.isDebugEnabled()) {
//			logger.debug("Huasheng UserInfo fetch result: {}, outerUserId: {} ", result, outerUserId);
//		}
//		JSONObject obj = JSONObject.parseObject(result);
//		JSONObject info = obj.getJSONObject("info");
//		Map<String, String> rtnDatas = new TreeMap<String, String>();
//		StringBuilder sb = new StringBuilder();
//		try {
//			for (String key : info.keySet()) {
//				String val = info.getString(key);
//				//  如果右sign  就跳过去继续循环
//				if ("sign".equalsIgnoreCase(key)) {
//					continue;
//				}
//				rtnDatas.put(key, val);
//				if (sb.length() > 0) {
//					sb.append("&");
//				}
//				sb.append(key);
//				sb.append("=");
//				sb.append(val);
//			}
//		} catch (Exception ex) {
//			ex.printStackTrace();
//		}
//		boolean signCheck = false;
//		try {
//			// 检查花生签名
//			signCheck = RSAUtil.verify(sb.toString().getBytes("utf-8"), huashengPubKey, obj.getString("sign"));
//		} catch (Exception e) {
//			e.printStackTrace();
//			logger.error(e.getMessage());
//		}
//		rtnDatas.put("signCheck", signCheck + "");
//		return rtnDatas;
//	}
}
