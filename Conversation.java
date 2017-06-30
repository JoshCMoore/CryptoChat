
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Chat conversation for CSC 580 chat program. Objects in this class represent
 * active chat conversations, and interact with the chat hub for communication
 * and a ChatView object to initiate/report chat actions. Note that this class
 * must be initialized with the setChatViewController static method before any
 * Conversation objects can be created.
 * 
 */
public class Conversation {
    enum ConvEncrState {
        ST_INIT, ST_WAITSPEC, ST_SENTKA, ST_GOTCERT, ST_ESTAB
    };

    private ConvEncrState state;

    public final static int STATUS_NOTCONN = 0;
    public final static int STATUS_CONN = 1;

    // One chat view controller for all conversations
    private static ChatViewController cvc;
    
    protected int id;
    protected int status;
    protected final String otherID;
    protected final HubSession hubConn;
    protected final ChatView view;

    private Cipher cipher;
    private SecretKeySpec keySpec;
    private GCMParameterSpec GCMSpec;

    private KeyPair thisKAPair;
    private byte[] keyBytes;
    
    private ChatKeyManager manager;
    private byte[] otherCert;
    private byte[] otherSig;
    private Signature mySig;
    
    private void setKAPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp224r1"));
            thisKAPair = kpg.genKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger(Conversation.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private void handle_error(String message) {
        hubConn.sendMessage(id, ":err " + message);
        view.addInfoMessage("*** ERROR: " + message);

    }

    private void handle_fail(String message) {
        hubConn.sendMessage(id, ":fail " + message);
        view.addInfoMessage("*** FATAL ERROR: " + message);

    }

    private boolean handleCtrlMsg(String msg) {
        String[] parts = msg.split("\\s+", 2);
        if (parts.length == 1) {
            System.out.println("Command |" + parts[0] + "| --- NO ARGUMENT GIVEN!!");
        } else {
            System.out.println("Command |" + parts[0] + "|,|" + parts[1] + "|");
        }
        if (parts[0].equals(":err")) {
            view.addInfoMessage("*** RECEIVED ERROR MSG: "+parts[1]);
            return true;
        } else if (parts[0].equals(":fail")) {
            view.addInfoMessage("*** RECEIVED FATAL ERROR MSG: "+parts[1]);
            return false;
        }
        switch (state) {
            case ST_INIT:
                if (parts[0].equals(":ka")) {
                	manager = hubConn.getLoginCredentials().getKeyManager();
                	String options[] = parts[1].split(",");
                    if ((parts.length == 2) && (Arrays.asList(options).contains("ecdh-secp224r1+x509+aes128/gcm128")||
                    		Arrays.asList(options).contains("ecdh-secp224r1+x509+aes128/cbc")||
                    		Arrays.asList(options).contains("ecdh-secp224r1+nocert+aes128/gcm128")||
                    		Arrays.asList(options).contains("ecdh-secp224r1+nocert+aes128/cbc"))) {
                        setKAPair();
                        hubConn.sendMessage(id, ":kaok ecdh-secp224r1+x509+aes128/gcm128");
                        hubConn.sendMessage(id, ":cert " + manager.getMyCertB64());
                        try{
	                        Signature mySig = Signature.getInstance(manager.getMyCert().getPublicKey().getAlgorithm());
	                        mySig.initSign(manager.getMyPrivateKey());
	                        mySig.update(thisKAPair.getPublic().getEncoded());
	                        hubConn.sendMessage(id, ":ka1 " + Base64.getEncoder().encodeToString(thisKAPair.getPublic().getEncoded()) + " " + Base64.getEncoder().encodeToString(mySig.sign()));
	                        state = ConvEncrState.ST_SENTKA;
                        }
                        catch(SignatureException | NoSuchAlgorithmException | InvalidKeyException e)
                        {
                        	handle_error("Signature Error");
                        }
                    } else {
                        handle_fail("Unexpected or missing key agreement parameters");
                        return false;
                    }
                } else {
                    handle_error("First control message not :ka - ignoring");
                    return true;
                }
                break;
            case ST_WAITSPEC:
                if (parts[0].equals(":kaok") && (parts.length == 2) && parts[1].equals("ecdh-secp224r1+x509+aes128/gcm128")) {
                    setKAPair();
                    try{
    	                Signature mySig = Signature.getInstance("SHA1withDSA");
    	                mySig.initSign(manager.getMyPrivateKey());
    	                mySig.update(thisKAPair.getPublic().getEncoded());
    	                hubConn.sendMessage(id, ":cert " + manager.getMyCertB64());
    					hubConn.sendMessage(id, ":ka1 " + Base64.getEncoder().encodeToString(thisKAPair.getPublic().getEncoded()) + " " + Base64.getEncoder().encodeToString(mySig.sign()));
    					state = ConvEncrState.ST_SENTKA;
                    }
                    catch(SignatureException | NoSuchAlgorithmException | InvalidKeyException e)
                    {
                    	handle_error("Signature Error");
                    }
                } else {
                    handle_error("Didn't get expected :kaok - ignoring message");
                    return true;
                }
                break;
                
            case ST_SENTKA:
            	if (!parts[0].equals(":cert") || (parts.length != 2)) {
                    handle_error("Didn't get expected :cert (or missing arg) - ignoring message");
                    return true;
                }
                if (parts[0].equals(":cert")) 
                {
                	otherCert = Base64.getDecoder().decode(parts[1].getBytes());
                	if(!manager.checkForCert(otherID, otherCert))
                		view.addInfoMessage("WARNING: THIS USER'S CERTIFICATE DOES NOT MATCH THE CERTIFICATE STORED");
                	else
                		view.addInfoMessage("*** THIS CERTIFICATE MATCHS THE CERTIFICATE ON FILE FOR THIS ID");
                	state = ConvEncrState.ST_GOTCERT;
                }
                break;
            case ST_GOTCERT:
                if (!parts[0].equals(":ka1") || (parts.length != 2) || parts[1].split(" ").length<2) {
                	System.out.println(parts[1]);
                	System.out.println(parts[1].split(" ").length);
                    handle_error("Didn't get expected :ka1 (or missing arg) - ignoring message");
                    return true;
                }
                String kaParts[] = parts[1].split(" ");
                if (parts[0].equals(":ka1")) {
                    PublicKey otherPubKey = null;
                    byte[] otherPubEnc = null;
                    try {
                        otherPubEnc = Base64.getDecoder().decode(kaParts[0]);
                        KeyFactory kf = KeyFactory.getInstance("EC");
                        otherPubKey = kf.generatePublic(new X509EncodedKeySpec(otherPubEnc));
                    } catch (IllegalArgumentException | NoSuchAlgorithmException | InvalidKeySpecException ex) {
                        Logger.getLogger(Conversation.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    try {
                        KeyAgreement aliceKA = KeyAgreement.getInstance("ECDH");
                        aliceKA.init(thisKAPair.getPrivate());
                        aliceKA.doPhase(otherPubKey, true);
                        byte[] aliceS = aliceKA.generateSecret();
                        System.out.println();
                        keyBytes = new byte[16];
                        System.arraycopy(aliceS, aliceS.length - 16, keyBytes, 0, 16);
                        keySpec = new SecretKeySpec(keyBytes, "AES");
                        GCMSpec = new GCMParameterSpec(128,keyBytes);
                    } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
                        Logger.getLogger(Conversation.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    otherSig = Base64.getDecoder().decode(kaParts[1].getBytes());
                    if(manager.verifyCertAndSig(otherID, otherCert, otherPubEnc, otherSig)!=null)
                    {
                    	handle_fail(manager.verifyCertAndSig(otherID, otherCert, otherPubEnc, otherSig));
                    	view.disconnectConvo();
                        view.addInfoMessage("*** DISCONNECTED FROM "+otherID);
                    }
                    else
                    	state = ConvEncrState.ST_ESTAB;
                }
                break;
            case ST_ESTAB:
            default:
        }
        return true;
    }

    private void initCrypto() {
        try {
            state = ConvEncrState.ST_INIT;
            byte[] keybytes = new byte[16];
            GCMParameterSpec s = new GCMParameterSpec(128,keybytes);
            cipher = Cipher.getInstance("AES/GCM/PKCS5Padding");
            keySpec = new SecretKeySpec(keybytes, "AES");
            manager = hubConn.getLoginCredentials().getKeyManager();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            Logger.getLogger(Conversation.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Initialize Conversation class with an object that allows for views to
     * be created appropriate to the application.
     * @param cvc_in
     */
    public static void setChatViewController(ChatViewController cvc_in) {
        cvc = cvc_in;
    }
    
    /**
     * Create a new conversation for an already-established conversation (one
     * that already has a session id from the chat hub). Starts the key exchange.
     * @param hub the logged-in chat hub session
     * @param sessionID the already-established session id
     * @param connTo the username on the other end of the connection
     */
    public Conversation(HubSession hub, int sessionID, String connTo) {
        status = STATUS_CONN;
        id = sessionID;
        otherID = connTo;
        hubConn = hub;
        view = cvc.newView(this);
        establish(id);
        initCrypto();
        hubConn.sendMessage(id, ":ka ecdh-secp224r1+x509+aes128/gcm128");
        state = ConvEncrState.ST_WAITSPEC;

    }

    /**
     * Create a new conversation object for a conversation that hasn't been
     * connected yet. This is created when the user makes a request for a new
     * chat conversation, but when the connection hasn't been acknowledged (and
     * a session id assigned) by the chat hub. Before this can be used, the
     * connection must be completed, and establish() must be called.
     * @param hub the logged-in chat hub session
     * @param sessionID the already-established session id
     * @param connTo the username on the other end of the connection
     */
    public Conversation(HubSession hub, String connTo) {
        status = STATUS_NOTCONN;
        hubConn = hub;
        otherID = connTo;
        view = cvc.newView(this);
        hub.connectRequest(this);
        initCrypto();
    }

    /**
     * Establish a session. This is called when a connection request is
     * completed and acknowledged by the chat hub.
     * @param id the session ID for this conversation
     */
    public void establish(int id) {
        this.id = id;
        this.status = STATUS_CONN;
        view.setConnStatus(true);
        view.addInfoMessage("*** CONNECTED to " + otherID);
    }

    /**
     * Call this when a connection attempt has been made, creating the
     * Conversation object, but the connection does not go through.
     */
    public void failed() {
        view.addInfoMessage("*** CONNECT ATTEMPT FAILED");
        view.disconnectConvo();
    }

    /** Bad convoID - dropping
     * Drop an active connection. Conversation object can't be use do send
     * or receive messages after this, unless a new conversation is established
     * through a call to establish().
     */
    public void drop() {
        if (STATUS_CONN == status) {
            hubConn.dropConvo(id);
            this.id = -1;
            this.status = STATUS_NOTCONN;
            view.setConnStatus(false);
            view.addInfoMessage("*** DISCONNECTED");
        }
    }

    /**
     * Get the identity of the other side of the chat conversation.
     * @return the other user name
     */
    public String getOtherID() {
        return otherID;
    }
    
    /**
     * Interacts with the chatkeymanager to pass the values stored in this class.
     * 
     */
    public void saveCert() {
    	X509Certificate otherPartyCertificate = null;
    	try {
    	CertificateFactory cf = CertificateFactory.getInstance("X.509");
		InputStream stream = new ByteArrayInputStream(otherCert);
		otherPartyCertificate = (X509Certificate) cf.generateCertificate(stream);
		} catch (CertificateException e) {
			e.printStackTrace();
		}
    	String result = manager.addPublicKey(otherID, otherPartyCertificate);
    	if(!result.equals(null))
    		view.addInfoMessage(result);
    }
    
    /**
     * Get all the info on the other user, and return in a form suitable for
     * a pop-up info window. For conversations in which parties are identified
     * by public keys, this could include the fingerprint of the other party's
     * certificate.
     * 
     * @return info on the other user
     */
    public String getOtherInfo() {
        return "Connected to: "+otherID+"\n"+
        		"Fingerprint:\n"+
        		manager.getFingerprint(otherCert);
    }
    
    private String myEncrypt(String plaintext) {
        String returnValue = null;
        try {
        	byte[] nonce = new byte[16];
        	SecureRandom.getInstanceStrong().nextBytes(nonce);
        	GCMSpec = new GCMParameterSpec(128, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, GCMSpec);
            byte[] ctext = cipher.doFinal(plaintext.getBytes());
            byte[] iv = cipher.getIV();
            byte[] combined = new byte[iv.length + ctext.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(ctext, 0, combined, iv.length, ctext.length);
            returnValue = Base64.getEncoder().encodeToString(combined);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException | NoSuchAlgorithmException ex) {
            Logger.getLogger(Conversation.class.getName()).log(Level.SEVERE, null, ex);
        }
        return returnValue;
    }

    private String myDecrypt(String ciphertext) {
    	System.out.println(ciphertext);
        String returnValue = null;
        try {
            byte[] binaryCiphertext = Base64.getDecoder().decode(ciphertext);
            if (binaryCiphertext.length < 32) {
                return null;
            }
            GCMSpec = new GCMParameterSpec(128,Arrays.copyOfRange(binaryCiphertext, 0, 16));
            cipher.init(Cipher.DECRYPT_MODE, keySpec, GCMSpec);
            returnValue = new String(cipher.doFinal(binaryCiphertext, 16, binaryCiphertext.length - 16));
        } catch (AEADBadTagException e){
        	handle_error("Tag Mismatch");
        } catch (IllegalArgumentException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger(Conversation.class.getName()).log(Level.SEVERE, null, ex);
        } 
        	
        return returnValue;
    }
    
    /**
     * Process a message that has been received as part of a conversation.
     * Basically just sends the message on to the view so it can be displayed
     * or processed.
     * 
     * @param message the message that was received
     */
    public void received(String ctext) {
//    	System.out.println(ctext);
        if ((ctext.length() > 0) && (ctext.charAt(0) == ':')) {
            if (!handleCtrlMsg(ctext)) {
                hubConn.dropConvo(id);
                view.disconnectConvo();
                // End conversation...  how?
            }
        } else if (state == ConvEncrState.ST_ESTAB) {
            String plaintext = myDecrypt(ctext);
            if (plaintext != null) {
                view.addReceivedMessage(this, plaintext);
            } else {
                handle_error("Received bad ciphertext");
            }
        } else {
            handle_error("Message received before crypto is established");
        }
    }

    /**
     * Send a message on an established conversation. Tells the hub to actually
     * transmit the message.
     * 
     * @param message the message to send
     */
    public void sendMessage(String message) {
        if (STATUS_CONN == status) {
            hubConn.sendMessage(id, myEncrypt(message));
        }
    }
}
