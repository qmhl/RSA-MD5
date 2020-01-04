package com.nfbank.util;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * 加解/解密密工具 RSA
 *
 * @author: chao
 * @date: 2019-10-09 15:08
 */
public final class RsaCoder {
	
	public static final String KEY_ALGORITHM = "RSA";
	private final KeyFactory keyFactory;
	/**
	 * 私钥
	 */
	private final PrivateKey priKey;
	/**
	 * 公钥
	 */
	private final PublicKey pubKey;

	/**根据公钥和私钥字符串
	 * 生成公钥和私钥  初始化
	 * @param publicKeyStrInBase64  公钥字符串
	 * @param privateKeyStrInBase64 私钥字符串
	 */
	public RsaCoder(String publicKeyStrInBase64, String privateKeyStrInBase64) throws Exception {
		keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		if (publicKeyStrInBase64 != null && publicKeyStrInBase64.length() > 0) {
			X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
					Base64.getDecoder().decode(publicKeyStrInBase64));
			pubKey = keyFactory.generatePublic(x509EncodedKeySpec);
		} else {
			pubKey = null;
		}
		if (privateKeyStrInBase64 != null && privateKeyStrInBase64.length() > 0) {
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
					Base64.getDecoder().decode(privateKeyStrInBase64));
			priKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
		} else {
			priKey = null;
		}
	}

	/**
	 * 根据私钥解密
	 *
	 * @param encryptedDataInBase64
	 * @return
	 * @throws Exception
	 */
	public String decryptByPrivateKey(String encryptedDataInBase64) throws Exception {
		return decrypt(encryptedDataInBase64, priKey);
	}

	/**
	 * 
	 *根据公钥解密
	 * @param encryptedDataInBase64
	 * @return
	 * @throws Exception
	 */
	public String decryptByPublicKey(String encryptedDataInBase64) throws Exception {
		return decrypt(encryptedDataInBase64, pubKey);
	}

	/**
	 * 
	 *根据公钥加密
	 * @param data
	 * @return
	 * @throws Exception
	 */
	public String encryptByPublicKey(String data) throws Exception {
		return encrypt(data, pubKey);
	}

	/**
	 * 根据私钥加密
	 *
	 * @param data
	 * @return
	 * @throws Exception
	 */
	public String encryptByPrivateKey(String data) throws Exception {
		return encrypt(data, priKey);
	}

	/**
	 * 加密
	 * @param data
	 * @param key
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	private String encrypt(String data, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes(StandardCharsets.UTF_8)));
	}

	/**
	 * 解密
	 * @param encryptedDataInBase64
	 * @param key
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	private String decrypt(String encryptedDataInBase64, Key key) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, key);
		return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedDataInBase64)), StandardCharsets.UTF_8);
	}
}
