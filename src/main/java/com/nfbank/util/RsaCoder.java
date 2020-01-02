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
	 * 
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
	 *
	 * @param encryptedDataInBase64
	 * @return
	 * @throws Exception
	 */
	public String decryptByPublicKey(String encryptedDataInBase64) throws Exception {
		return decrypt(encryptedDataInBase64, pubKey);
	}

	/**
	 * 
	 *
	 * @param data
	 * @return
	 * @throws Exception
	 */
	public String encryptByPublicKey(String data) throws Exception {
		return encrypt(data, pubKey);
	}

	/**
	 * 
	 *
	 * @param data
	 * @return
	 * @throws Exception
	 */
	public String encryptByPrivateKey(String data) throws Exception {
		return encrypt(data, priKey);
	}

	private String encrypt(String data, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes(StandardCharsets.UTF_8)));
	}

	private String decrypt(String encryptedDataInBase64, Key key) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, key);
		return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedDataInBase64)), StandardCharsets.UTF_8);
	}
}
