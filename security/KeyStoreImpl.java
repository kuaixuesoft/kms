package com.tuniu.finance.xff.auth.security;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import javax.crypto.Cipher;
import org.apache.mina.util.Base64;
import org.springframework.beans.factory.InitializingBean;

public class KeyStoreImpl implements IKeyStore, InitializingBean {

	private String path;
	private String password;
	private String certificateAlias;
	private String certificatePassword;

	private PublicKey publicKey;
	private PrivateKey privateKey;

	protected PublicKey getPublicKey() {
		KeyStore ks;
		PublicKey pubkey = null;
		try {
			ks = KeyStore.getInstance("JKS");
			FileInputStream fin;
			fin = new FileInputStream(path);
			ks.load(fin, password.toCharArray());
			Certificate cert = ks.getCertificate(certificateAlias);
			pubkey = cert.getPublicKey();
		} catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
			throw new RuntimeException(e);
		}
		return pubkey;
	}

	protected PrivateKey getPrivateKey() {
		KeyStore ks;
		PrivateKey prikey = null;
		try {
			ks = KeyStore.getInstance("JKS");
			FileInputStream fin;
			fin = new FileInputStream(path);
			ks.load(fin, password.toCharArray());
			prikey = (PrivateKey) ks.getKey(certificateAlias, certificatePassword.toCharArray());
		} catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException
				| UnrecoverableKeyException e) {
			throw new RuntimeException(e);
		}
		return prikey;
	}

	protected String encrypt(Key key, String src) {
		if (key == null) {
			return null;
		}
		byte[] data = string2Bytes(src);
		try {
			Cipher cipher = Cipher.getInstance("RSA", new org.bouncycastle.jce.provider.BouncyCastleProvider());
			cipher.init(Cipher.ENCRYPT_MODE, key);
			int blockSize = cipher.getBlockSize();// 获得加密块大小，如：加密前数据为128个
			// byte，而key_size=1024
			// 加密块大小为127
			// byte,加密后为128个byte;因此共有2个加密块，第一个127
			// byte第二个 为1个byte
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
				// 这里面doUpdate方法不可用，查看源代码后发现每次doUpdate后并没有什么实际动作除了把byte[]放到
				// ByteArrayOutputStream中，而最后doFinal的时候才将所有的byte[]进行加密，可是到了此时加密块大小很可能已经超出了
				// OutputSize所以只好用dofinal方法。
				i++;
			}
			return bytes2StringBase64Encode(raw);// 由于输出的东东要经过URL等传送，所以用base64加密后传送
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	protected String decrypt(Key key, String src) {
		if (key == null) {
			return null;
		}
		byte[] raw = string2BytesBase64Decode(src);// 由于传送前进行了base64加密，所以在解码前先BASE64解密
		try {
			Cipher cipher = Cipher.getInstance("RSA", new org.bouncycastle.jce.provider.BouncyCastleProvider());
			cipher.init(Cipher.DECRYPT_MODE, key);
			int blockSize = cipher.getBlockSize();
			ByteArrayOutputStream bout = new ByteArrayOutputStream(64);
			int j = 0;

			while (raw.length - j * blockSize > 0) {
				bout.write(cipher.doFinal(raw, j * blockSize, blockSize));
				j++;
			}
			return bytes2String(bout.toByteArray());
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	protected String bytes2String(byte[] bts) {
		String str = "";
		try {
			str = new String(bts, "utf-8");
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
		return str;
	}

	protected String bytes2StringBase64Encode(byte[] bts) {
		Base64 base64 = new Base64();
		byte[] enbytes;
		String str = "";
		try {
			enbytes = base64.encode(bts);
			str = new String(enbytes, "utf-8");
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
		return str;
	}

	protected byte[] string2Bytes(String str) {
		byte[] debytes = null;
		try {
			debytes = str.getBytes("utf-8");
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
		return debytes;
	}

	protected byte[] string2BytesBase64Decode(String s) {
		Base64 base64 = new Base64();
		byte[] debytes = null;
		try {
			debytes = base64.decode(s.getBytes("utf-8"));
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
		return debytes;
	}		

	public void setPath(String path) {
		this.path = path;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public void setCertificateAlias(String certificateAlias) {
		this.certificateAlias = certificateAlias;
	}

	public void setCertificatePassword(String certificatePassword) {
		this.certificatePassword = certificatePassword;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		publicKey = getPublicKey();
		privateKey = getPrivateKey();
	}
	
	@Override
	public String encryptByPublicKey(String cleartext){
		return encrypt(publicKey, cleartext);
	}
	
	@Override
	public String decryptByPrivateKey(String ciphertext){
		return decrypt(privateKey, ciphertext);
	}

}
