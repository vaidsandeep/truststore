package trust.store.sandeep.vaid;



import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;


/*import com.ibm.ws.crypto.config.KeyReference;
import com.ibm.ws.crypto.config.KeySetManager;
import com.ibm.ws.crypto.config.WSKeySet;
import com.ibm.ws.ssl.config.KeyStoreManager;
import com.ibm.ws.ssl.config.WSKeyStore;*/

/**
 * 
 */

//CHECKSTYLE:OFF
public class FileIntegrityCheckAction  {



 

    private String signatureAlgo;

  
    protected void execute(String encodedHash,String filePath) {
      
        if (encodedHash != null) {
            byte[] encryptedHash = null;
            try {
                encryptedHash = Base64.decodeBase64(encodedHash.getBytes());
            } catch (Exception e) {
                e.printStackTrace();
            }
            try {
                Signature signature = Signature.getInstance(signatureAlgo);
                String keySetName = getKeySetName();
                PublicKey publicKey = getPublicKey(keySetName);
                signature.initVerify(publicKey);
                FileInputStream fis = new FileInputStream(new File(filePath));
                BufferedInputStream bufferedInputStream = new BufferedInputStream(fis);
                byte[] buffer = new byte[2048];
                int read = 0;
                while ((read = bufferedInputStream.read(buffer)) > 0) {
                    signature.update(buffer, 0, read);
                }

                boolean isVerified = signature.verify(encryptedHash);
               System.out.println("signature varified for file "+ filePath);
            } catch (Exception e) {
               e.printStackTrace();
            }
        }

    }
    
    /**
     * 
     * @return private Key from parameter Service
     */
    private String getKeySetName() {
        return "publicCertKeySet";
    }
    
    /**
     * Need to use IBM jar (com.ibm.runtime.ws.runtime.jar) to compile but not to bundle as it is provide jar
     * @param keySetName
     * @return
     */

   private PublicKey getPublicKey(String keySetName) {
	   /*
        WSKeySet keySet = KeySetManager.getInstance().getKeySet(keySetName);

        KeyReference[] allKeyReferences = keySet.getAllKeyReferences();

        for (int i = 0; i < allKeyReferences.length; ++i) {

            try {
                KeyReference kref = allKeyReferences[i];
                String keyAlias = kref.getKeyAlias();

                WSKeyStore wsKeyStore = kref.getWSKeyStore();
                String location = wsKeyStore.getLocation();

                String type = wsKeyStore.getProperty("com.ibm.ssl.keyStoreType");

                String name = wsKeyStore.getProperty("com.ibm.ssl.keyStoreName");
                //            String type = keyStore.getProperty("com.ibm.ssl.keyStoreType");
                String provider = wsKeyStore.getProperty("com.ibm.ssl.keyStoreProvider");
                //            String location = keyStore.getProperty("com.ibm.ssl.keyStore");
                String kspassword = wsKeyStore.getProperty("com.ibm.ssl.keyStorePassword");
                String scope = wsKeyStore.getProperty("com.ibm.ssl.keyStoreScope");

                KeyStore keyStore =
                    KeyStoreManager.getInstance().getKeyStore(name, type, provider, location, kspassword, scope,
                            true, null);
                Certificate certificate = keyStore.getCertificate(keyAlias);
                PublicKey publicKey = certificate.getPublicKey();

                return publicKey;
            } catch (Exception e) {

                System.out.println("Not able to load WAS Keyset public key ");
                e.printStackTrace();
            }

        }
        */
        return null;
    }

    
   

    /**
     * Reads File in Bytes
     * @param filename FileName
     * @return file contents in Bytes
     * @throws IOException IOException
     */
    public byte[] readFileBytes(String filename) throws IOException {
        FileInputStream inputStream = null;
        try {
            inputStream = new FileInputStream(filename);
            return IOUtils.toByteArray(inputStream);
        } finally {
            if (inputStream != null) {
                inputStream.close();
            }
        }

    }

   
}

