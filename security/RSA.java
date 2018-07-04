package com.tuniu.finance.xff.auth.security;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.*;

public class RSA {
	protected static String encrypt(String plainText, Cipher cipher, Key key)
			throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, ShortBufferException,
			IllegalBlockSizeException, BadPaddingException, InvalidKeyException {

		byte[] data = plainText.getBytes("utf-8");
		int blockSize = cipher.getBlockSize();// 获得加密块大小，如：加密前数据为128个
		int outputSize = cipher.getOutputSize(data.length);// 获得加密块加密后块大小
		int leavedSize = data.length % blockSize;
		int blocksSize = leavedSize != 0 ? data.length / blockSize + 1 : data.length / blockSize;
		byte[] raw = new byte[outputSize * blocksSize];
		int i = 0;
		while (data.length - i * blockSize > 0) {
			if (data.length - i * blockSize > blockSize) {
				cipher.doFinal(data, i * blockSize, blockSize, raw, i * outputSize);
			} else {
				cipher.doFinal(data, i * blockSize, data.length - i * blockSize, raw, i * outputSize);
			}
			i++;
		}
		return Hex.encodeHexString(raw);
	}

	protected static String decrypt(String cipherText, Cipher cipher, Key key)
			throws DecoderException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, IOException {

		byte[] raw = Hex.decodeHex(cipherText.toCharArray());
		int blockSize = cipher.getBlockSize();
		ByteArrayOutputStream bout = new ByteArrayOutputStream(64);
		int j = 0;
		while (raw.length - j * blockSize > 0) {
			bout.write(cipher.doFinal(raw, j * blockSize, blockSize));
			j++;
		}
		return new String(bout.toByteArray(), "utf-8");
	}

	public static RSACipherSpec getCipherSpec(PublicKey publicKey, PrivateKey privateKey, CryptoType type)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		RSACipherSpec cipherSpec = new RSACipherSpec();
		Cipher cipher = Cipher.getInstance("RSA", new org.bouncycastle.jce.provider.BouncyCastleProvider());
		cipherSpec.setCipher(cipher);
		cipherSpec.setPublicKey(publicKey);
		cipherSpec.setPrivateKey(privateKey);
		cipherSpec.setType(type);
		return cipherSpec;
	}

	public static String process(String text, RSACipherSpec cipherSpec)
			throws DecoderException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
			NoSuchAlgorithmException, NoSuchPaddingException, ShortBufferException, IOException {
		if (text == null)
			return text;

		Cipher cipher = cipherSpec.getCipher();
		PublicKey publicKey = cipherSpec.getPublicKey();
		PrivateKey privateKey = cipherSpec.getPrivateKey();

		if (cipherSpec.getType() == CryptoType.ENCRYPT) {
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			return encrypt(text, cipher, publicKey);
		} else if (cipherSpec.getType() == CryptoType.DECRYPT) {
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			return decrypt(text, cipher, privateKey);
		} else if (cipherSpec.getType() == CryptoType.SIGN) {
			cipher.init(Cipher.ENCRYPT_MODE, privateKey);
			return encrypt(text, cipher, privateKey);
		} else if (cipherSpec.getType() == CryptoType.VALIDATE) {
			cipher.init(Cipher.DECRYPT_MODE, publicKey);
			return decrypt(text, cipher, publicKey);
		} else {
			throw new IllegalArgumentException(cipherSpec.getType() + " is not supported by RSA");
		}

	}
}
