
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

public class LoginCredentials {
    private String userID;
    private String password;
    private ChatKeyManager keyManager;
    
    public LoginCredentials(String userID, String password) {
        this.userID = userID;
        this.password = password;
        this.keyManager = null;
    }

    public LoginCredentials(ChatKeyManager keyManager) {
        this.keyManager = keyManager;
        this.userID = keyManager.getUsername();
        this.password = null;
    }

    public ChatKeyManager getKeyManager() {
        return keyManager;
    }
    
    public String getUserID() {
        if (password != null) {
            return userID;
        } else {
            return "pubkey "+userID;
        }
    }
    
    /**
     * Takes the challenge, signs it with private key, and returns
     * @param challenge the string received that must be signed and returned
     * @return
     */
    public String answerChallenge(String challenge) {
        if (password != null) {
            return password;
        } else {
        	String answer = "";
        	challenge = "login-"+challenge;
        	try {
				Signature sig = Signature.getInstance("SHA1withDSA");
				sig.initSign(keyManager.getMyPrivateKey());
				sig.update(challenge.getBytes());
				answer = keyManager.getMyCertB64() + " " + Base64.getEncoder().encodeToString(sig.sign());
			} catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
				e.printStackTrace();
			}
            return answer;
        }
    }   
}
