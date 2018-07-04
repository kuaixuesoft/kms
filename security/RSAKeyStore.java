package com.tuniu.finance.xff.auth.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class RSAKeyStore {
	private static final Logger LOGGER = LoggerFactory.getLogger(RSAKeyStore.class);

	public static PublicKey getPublicKey(String path, String storePassword, String alias)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		KeyStore ks;
		PublicKey pubkey = null;

		ks = KeyStore.getInstance("JKS");
		FileInputStream fin = null;
		try {
			fin = new FileInputStream(path);
			ks.load(fin, storePassword.toCharArray());
			Certificate cert = ks.getCertificate(alias);
			pubkey = cert.getPublicKey();
		} finally {
			if (fin != null)
				try {
					fin.close();
				} catch (IOException e) {
					LOGGER.error("failed to close: {}", path);
				}
		}
		return pubkey;
	}

	public static PrivateKey getPrivateKey(String path, String storePassword, String alias, String keyPassword)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
			UnrecoverableKeyException {
		KeyStore ks;
		PrivateKey prikey = null;
		ks = KeyStore.getInstance("JKS");
		FileInputStream fin = null;
		try {
			fin = new FileInputStream(path);
			ks.load(fin, storePassword.toCharArray());
			prikey = (PrivateKey) ks.getKey(alias, keyPassword.toCharArray());
		} finally {
			if (fin != null)
				try {
					fin.close();
				} catch (IOException e) {
					LOGGER.error("failed to close: {}", path);
				}
		}
		return prikey;
	}
}
