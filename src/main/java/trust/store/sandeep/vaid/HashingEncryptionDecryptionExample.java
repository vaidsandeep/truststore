package trust.store.sandeep.vaid;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.DigestInputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Formatter;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;

public class HashingEncryptionDecryptionExample {
	public static byte[] readFileBytes(String filename) throws IOException {
		InputStream resourceAsStream = HashingEncryptionDecryptionExample.class.getClassLoader()
				.getResourceAsStream(filename);

		return IOUtils.toByteArray(resourceAsStream);

	}

	public static PublicKey readPublicKey(String filename)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(readFileBytes(filename));
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return keyFactory.generatePublic(publicSpec);
	}

	public static PrivateKey readPrivateKey(String filename)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(readFileBytes(filename));
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return keyFactory.generatePrivate(keySpec);
	}

	public static byte[] encrypt(Key key, byte[] plaintext) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(plaintext);
	}

	public static byte[] decrypt(Key key, byte[] ciphertext) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(ciphertext);
	}

	public static void main(String[] args) {
		try {
			Key publicKey = readPublicKey("./resources/public.der");
			Key privateKey = readPrivateKey("./resources/private.der");
			HashingEncryptionDecryptionExample testEncry = new HashingEncryptionDecryptionExample();
			String fileHash = testEncry.getFileHash("./resources/test-file.txt");
			byte[] message = fileHash.getBytes("UTF8");
			byte[] secret = encrypt(privateKey, message);
			byte[] encodedSecret = Base64.encodeBase64(secret);
			byte[] decodeBase64 = Base64.decodeBase64(encodedSecret);
			byte[] recovered_message = decrypt(publicKey, decodeBase64);
			String hashRevisted = new String(recovered_message, "UTF8");
//			System.out.println(hashRevisted);
			if (!fileHash.equals(hashRevisted)) {
				System.out.println(" ERROR!!");
			} else {
				System.out.println(" HASH MATCHED ----PASS!!!");
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private String getFileHash(String filepath) throws NoSuchAlgorithmException, IOException {
		long currentTimeMillis = System.currentTimeMillis();

		InputStream resourceAsStream = HashingEncryptionDecryptionExample.class.getClassLoader()
				.getResourceAsStream(filepath);
		DigestInputStream in = new DigestInputStream(new BufferedInputStream(resourceAsStream),
				MessageDigest.getInstance("SHA-256"));

		Formatter formatter = new Formatter();

		while (in.read() != -1) {
		}

		// Get the digest and finialise the computation
		final MessageDigest md = in.getMessageDigest();
		final byte[] digest = md.digest();
		for (final byte b : digest) {
			formatter.format("%02x", b);
		}

		final String sha256 = formatter.toString();
		/*System.out.println(sha256);
		System.out.println(" time in millis is " + (System.currentTimeMillis() - currentTimeMillis));*/
		return sha256;

	}
}