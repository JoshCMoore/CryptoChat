import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.Formatter;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.EncryptedPrivateKeyInfo;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;



/**
 * This class manages public keypairs for the CSC 580 chat system. The
 * constructors set up the keystore to be used, and the user must remember to
 * invoke the close() method when finished so that any changes are saved when
 * the application exits.
 * 
 * @author srt
 */
public class ChatKeyManager {    
    private final static String DEFAULTPW = "password";
    private final static String KEYSTORE_FILE = "chatapp.ks";
    
    private final String actualFilename;
    private final String actualPassword;
    
    private KeyStore keyStore;
    private String myUsername;
    
    private Key myKeyPair;
    private Certificate myCert;

    // Hard-coded Certification Authority certificate. This is not very flexible,
    // of course, since revoking this key would require a software update in
    // each client. A real, productin system would need to handle this better...
    final private static String CA_CERT_TEXT = 
      "-----BEGIN CERTIFICATE-----\n"+
      "MIID8DCCAtigAwIBAgIJAKClo2Hhuu2+MA0GCSqGSIb3DQEBCwUAMIGEMQswCQYD\n"+
      "VQQGEwJVUzELMAkGA1UECAwCTkMxEzARBgNVBAcMCkdyZWVuc2Jvcm8xDTALBgNV\n"+
      "BAoMBFVOQ0cxEDAOBgNVBAsMB0NTQyA1ODAxEjAQBgNVBAMMCUNTQzU4MC1DQTEe\n"+
      "MBwGCSqGSIb3DQEJARYPc3J0YXRlQHVuY2cuZWR1MB4XDTE3MDMwMzE1NTcwNFoX\n"+
      "DTE4MDMwMzE1NTcwNFowgYQxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJOQzETMBEG\n"+
      "A1UEBwwKR3JlZW5zYm9ybzENMAsGA1UECgwEVU5DRzEQMA4GA1UECwwHQ1NDIDU4\n"+
      "MDESMBAGA1UEAwwJQ1NDNTgwLUNBMR4wHAYJKoZIhvcNAQkBFg9zcnRhdGVAdW5j\n"+
      "Zy5lZHUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDsB23ceLXplGQB\n"+
      "jCoGLkUE2cyjW10gJPkrjc5yS0Ysx+7oIvwCQBJcLJIo97Edc0fDq5Zam6kBZ5dj\n"+
      "sAZRLThAePmOz70OePXZtwLak+fRusIH6wVirtG9QqMx5JvEbvZFuGnhCz7KrXd5\n"+
      "eNaD8/7TWFGY97KDzOs15PxScKNuka1DLfM/A6xaaV69tKS7Hbt2h+W5u5G3YElo\n"+
      "Qhq+V0YJPN7noB07C4J/lq2lVunzmCwtw5VFJJwdmIfWOTMn46QtzOdwHpCLb5LZ\n"+
      "LdgLf/s0tkVXjwQmNhEpQghzDNckqyu4yioPPIb+AXiwXcrwniyyjOMEWKQP6kj1\n"+
      "TJSMMSD1AgMBAAGjYzBhMB0GA1UdDgQWBBRZR8/M/5UISB1s/Kc/dCmB4IiKbzAf\n"+
      "BgNVHSMEGDAWgBRZR8/M/5UISB1s/Kc/dCmB4IiKbzAPBgNVHRMBAf8EBTADAQH/\n"+
      "MA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAQEAgPjcJ78s2Ac7gkG7\n"+
      "h1uwWxY+Pvv9wImaHSxUxPDiocoVYPgfp69zrqWnLbGEol8it5XusgWcY0Giq2I5\n"+
      "dtwLD6MxzYbmdLqS1eM7TA1z0IJuiLr1vGKTDFqN347U9nZHlAHB3KC6vKrbQCX/\n"+
      "otyhC8mM02A9E/tfVtUGu63plDWlvDJTnFBLlwE5xiPYCWTp3m3rcNBez9F5gaRl\n"+
      "3+QlvFCNqDiYReuHQQ5z8uy4B9E+EzrTrqjoN6HYjHO1spEWxBbcQok0+f9IIaFp\n"+
      "wxCybY49cLtO254tQBc7ZmRE4L/7pv0KwqTjcnXa8/zFXt6bajVQZ5rg6E2zAjX/\n"+
      "8vYr5w==\n"+
      "-----END CERTIFICATE-----";

    private static final X509Certificate CA_CERT = caCertInit();
    private static PublicKey caPubKey;
    
    // A static method - just used to load in the hard-coded CA Certificate
    // defined above.
    private static X509Certificate caCertInit() {
        X509Certificate retValue = null;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            InputStream stream = new ByteArrayInputStream(CA_CERT_TEXT.getBytes(StandardCharsets.UTF_8));
            retValue = (X509Certificate) cf.generateCertificate(stream);
        } catch (CertificateException ex) {
            Logger.getLogger(ChatKeyManager.class.getName()).log(Level.SEVERE, null, ex);
        }   
        return retValue;
    }

    /**
     * This constructor loads the keystore to prepare for use, using the default
     * filename (defined in KEYSTORE_FILE) and password (defined in DEFAULTPW).
     * The keypair for the user is also located and loaded in this class for easy
     * subsequent use - the string "mykey-" is prepended to the value passed
     * as a parameter as the key alias to use (e.g., if the username is "fred"
     * then the key with alias "mykey-fred" is loaded).
     * 
     * @param myUserName
     */
    public ChatKeyManager(String myUserName) {
        this(myUserName, KEYSTORE_FILE, DEFAULTPW);
        if (caPubKey == null) {
            caPubKey = CA_CERT.getPublicKey();
        }
    }

    /**
     *
     * @param myUserName
     * @param filename where the keystore is saved
     * @param password
     */
    public ChatKeyManager(String myUserName, String filename, String password) {
        this.myUsername = myUserName;
        actualFilename = filename;
        actualPassword = password;
        try {
        	
            keyStore = KeyStore.getInstance("jks");
            InputStream fin = null;
            try {
                fin = new FileInputStream(filename);
                keyStore.load(fin, password.toCharArray());
            } catch (FileNotFoundException ex) {
                System.out.println("No file...");
                keyStore.load(null, null);
            }
            myKeyPair = keyStore.getKey("mykey-"+myUserName, password.toCharArray());
            if (myKeyPair != null) {
                myCert = keyStore.getCertificate("mykey-"+myUserName);
            } else {
                // How to handle this?
                System.out.println("Warning: Your main keypair not in keystore!");
            }
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException ex) {
        	
            Logger.getLogger(ChatKeyManager.class.getName()).log(Level.SEVERE, null, ex);
        }   
    }
    
    /**
     * Adds certificate of current party to the keystore under the alias
     * of the given id and saves the keystore to original file.
     * @param id of current party
     * @param otherParty certificate of current party
     * @return status certificate addition
     */
    public String addPublicKey(String id, X509Certificate otherParty) {
    	try {
    		X509Certificate cert[] = {otherParty, CA_CERT};
    		keyStore = KeyStore.getInstance("jks");
            InputStream fin = null;
            try {
                fin = new FileInputStream(actualFilename);
                keyStore.load(fin, actualPassword.toCharArray());
            } catch (FileNotFoundException ex) {
                System.out.println("No file...");
                keyStore.load(null, null);
            }
            if(keyStore.containsAlias(id))
            	return "*** ALREADY STORED";
            keyStore.setCertificateEntry(id, otherParty);
			OutputStream keyStream = new FileOutputStream(actualFilename);
			keyStore.store(keyStream, actualPassword.toCharArray());
			keyStream.flush();
			keyStream.close();
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			return "*** SOMETHING WENT WRONG";
		}
    	return "*** ADDED";
    }
    
    /**
     * Checks to see if the id of the party you are trying to 
     * connect to is already in the keystore. If it is, check
     * to see if the certificate given matchs the certificate
     * on file.
     * @param id of other party
     * @param otherParty certificate of other party
     * @return true if the party can be trusted, false otherwise
     */
    public boolean checkForCert(String id, byte[] otherParty)
    {
    	try{
	    	CertificateFactory cf = CertificateFactory.getInstance("X.509");
			InputStream stream = new ByteArrayInputStream(otherParty);
			X509Certificate otherPartyCertificate = (X509Certificate) cf.generateCertificate(stream);
			
			keyStore = KeyStore.getInstance("jks");
            InputStream fin = null;
            try {
                fin = new FileInputStream(actualFilename);
                keyStore.load(fin, actualPassword.toCharArray());
            } catch (NoSuchAlgorithmException | IOException ex) {
                System.out.println("No file...");
                try {
					keyStore.load(null, null);
				} catch (NoSuchAlgorithmException | IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
            }
            if(keyStore.containsAlias(id))
            {
            	if(!keyStore.getCertificate(id).equals(otherPartyCertificate))
            		return false;
            }
    	} catch(CertificateException | KeyStoreException e){
    		System.out.println("Something went wrong in the keystore");
    	}
    	return true;
    }

    // Routine to pull the common name (CN) out of the full X509
    // identifier. The CN is the chat system's username.
    private static String getCNfromName(String name) {
        try {
            LdapName ldapDN = new LdapName(name);
            for (Rdn r : ldapDN.getRdns()) {
                if (r.getType().equalsIgnoreCase("cn")) {
                    return (String) r.getValue();
                }
            }
        } catch (InvalidNameException ex) {
            // Nothing to do - just fall through to returning empty string
        }
        return "";
    }
    
    /**
     * This function verifies that the provided certificate is good and that
     * the corresponding private key was used to sign the provided data. There
     * are a lot of things to check: that the cert parameter contains a properly
     * formatted certificate; that the certificate hasn't expired; that the
     * certificate is signed by the trusted system CA; that the CN in the
     * certificate matches the claimed identity of the other party; and that
     * the sig parameter is a valid signature on data with the verification
     * key in the certificate. If any check fails, this method returns a
     * string describing the failure (e.g., "invalid certificate"). If all
     * tests pass, then this method returns null.
     * 
     * @param otherParty the claimed identity (username) of the remote party
     * @param cert the certificate provided by the remote party
     * @param data the data that the other party is claiming to have signed
     * @param sig the signature
     * @return an error string if there was a problem, or null if all was OK
     */
    public String verifyCertAndSig(String otherParty, byte[] cert, byte[] data, byte[] sig) {        
        try {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			InputStream stream = new ByteArrayInputStream(cert);
			X509Certificate otherPartyCertificate = (X509Certificate) cf.generateCertificate(stream);
			
			if(!(otherParty.equals(getCNfromName(new String(otherPartyCertificate.getSubjectX500Principal().getName())))))
	        {
	        	return "Commen Name in the certificate does not match your claimed identity";
	        }
			
			try {
				otherPartyCertificate.verify(caPubKey);
			} catch (InvalidKeyException e) {
				return "Not signed by CA";
			} catch (Exception e) {
				return "Could Not Verify signature";
			} 
			
			try {
				otherPartyCertificate.checkValidity(new Date());
			} catch (CertificateExpiredException e){
				return "Expired Certificate";
			} catch (CertificateNotYetValidException e){
				return "Certificate not yet valid";
			}
			
			try {
				Signature otherP = Signature.getInstance(otherPartyCertificate.getPublicKey().getAlgorithm());
				otherP.initVerify(otherPartyCertificate);
				otherP.update(data);
				if(!otherP.verify(sig))
				{
					return "Signature mismatch";
				}
			} catch (NoSuchAlgorithmException|SignatureException | InvalidKeyException e) {
				e.printStackTrace();
			}
			
		
		} catch (CertificateException e) {
			System.out.println(e);
		}
        return null;
    }

    /**
     * Returns a formatted string that gives a fingerprint of the provided
     * certificate. This is useful in the chat program for being able to show
     * the fingerprint of the party you are chatting with. The fingerprint is
     * the SHA1 digest of the certificate, formatted as 20 hexadecimal bytes
     * separated by colons.
     * @param cert the certificate you want the fingerprint for
     * @return a formatted fingerprint string
     */
    public static String getFingerprint(byte[] cert) {
        if (cert == null) {
            return "(No certificate)";
        }
        try {
			MessageDigest hash = MessageDigest.getInstance("SHA-1");
			hash.update(cert);
			String out="";
			for(byte b:hash.digest())
			{
				out+=String.format("%02X:", b);
			}
			if(out.length()>1)
				out=out.substring(0,out.length()-1);
	        return out;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} 
        return "something went wrong";
    }

    /**
     * Returns your username (used when this object was constructed)
     * @return your username
     */
    public String getUsername() {
        return myUsername;
    }
    
    /**
     * Returns your X509 certificate - this will have been loaded from the
     * keystore when the ChatKeyManager object was constructed.
     * @return your certificate
     */
    public Certificate getMyCert() {
        return myCert;
    }
    
    /**
     * Returns a Base64-encoded string for your certificate.
     * @return the Base64-encoded certificate (empty string if no certificate)
     */
    public String getMyCertB64() {
        try {
            return Base64.getEncoder().encodeToString(myCert.getEncoded());
        } catch (CertificateEncodingException ex) {
            return "";
        }
    }
    
    /**
     * Gets your private key - this is so that you can sign challenges, either
     * from the chathub when you log in or when you connect to another party
     * and you need to sign your :ka1 message.
     * @return your PrivateKey
     */
    public PrivateKey getMyPrivateKey() {
        return (PrivateKey) myKeyPair;
    }
    
    /**
     * The close method saves changes in the keystore to the underlying file.
     * Remember to call this before the program exits if you have made any
     * changes (e.g., if you used addPublicKey).
     */
    public void close() {
        try {
            keyStore.store(new FileOutputStream(actualFilename), actualPassword.toCharArray());
            keyStore = null;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException ex) {
            Logger.getLogger(ChatKeyManager.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
