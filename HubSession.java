import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.swing.SwingWorker;
public class HubSession {
    private static final String HUB_HOST = "scode.uncg.edu";
    private static final int HUB_PORT = 8008;
    
    // Hub session states
    private final static int STATE_INIT = 0;
    private final static int STATE_NOAUTH = 1;
    private final static int STATE_INAUTH1 = 2;
    private final static int STATE_INAUTH2 = 3;    
    private final static int STATE_CONNWAIT = 4;
    private final static int STATE_ACTIVE = 5;
    
    private Socket chatHubSock;
    private BufferedReader fromHub;
    private PrintWriter toHub;
    private int state;
    private Conversation pendingConn;
    private Map<Integer,Conversation> allConvos;
    private LoginCredentials credentials;

    private SwingWorker netlistener;
    
    public HubSession(LoginCredentials loginInfo) {
        state = STATE_INIT;
        pendingConn = null;
        allConvos = new HashMap<>();
        credentials = loginInfo;
        try {
            chatHubSock = new Socket(HUB_HOST, HUB_PORT);
            fromHub = new BufferedReader(new InputStreamReader(chatHubSock.getInputStream()));
            toHub = new PrintWriter(chatHubSock.getOutputStream(), true);
        } catch (IOException ex) {
            Logger.getLogger(HubSession.class.getName()).log(Level.SEVERE, null, ex);
        }

        netlistener = new SwingWorker<Boolean, Void>() {
            @Override
            protected Boolean doInBackground() throws Exception {
                boolean done = false;
                while (!done) {
                    String line = fromHub.readLine();
                    switch (state) {
                        case STATE_INIT:
                            if (line.startsWith("SpartanChat ")) {
                                toHub.println("login " + credentials.getUserID());
                                state = STATE_INAUTH1;
                            } else {
                                System.out.println("Didn't receive welcome banner - right host/port?");
                            }
                            break;
                            
                        case STATE_INAUTH1:
                            if (line.startsWith("challenge ")) {
                                toHub.println("answer " + credentials.answerChallenge(line.substring(10)));
                                state = STATE_INAUTH2;
                            } else {
                                System.out.println("should have gotten challenge");
                                return true;
                            }
                            break;
                            
                        case STATE_INAUTH2:
                            if (line.startsWith("OK")) {
                                System.out.println("Logged in!");
                                state = STATE_ACTIVE;
                            } else {
                                System.out.println("Login failed");
                                return true;
                            }
                            break;
                            
                        case STATE_CONNWAIT:
                            if (line.startsWith("OK ")) {
                                int connNum = Integer.parseInt(line.substring(3));
                                pendingConn.establish(connNum);
                                allConvos.put(connNum, pendingConn);
                                pendingConn = null;
                            } else if (line.startsWith("FAIL")) {
                                System.out.println("CONNECTION FAIL - could not connect to " + pendingConn.getOtherID());
                                pendingConn.failed();
                                pendingConn = null;
                            } else {
                                System.out.println("Unexpected server response: " + line);
                            }
                            state = STATE_ACTIVE;
                            break;
                            
                        case STATE_ACTIVE:
                            String[] parts = line.split("\\s+", 3);
                            if (parts.length >= 2) {
                                int convoID = Integer.parseInt(parts[1]);
                                if (parts[0].equals("connfrom")) {
                                    Conversation newConvo = new Conversation(HubSession.this, convoID, parts[2]);
                                    allConvos.put(convoID, newConvo);
                                } else {
                                    Conversation convo = allConvos.get(convoID);
                                    if (convo != null) {
                                        if (parts[0].equals("recv")) {
                                            if (parts.length > 2) {
                                                convo.received(parts[2]);
                                            } else {
                                                convo.received("");
                                            }
                                        } else if (parts[0].equals("drop")) {
                                            System.out.println("drop convo");
                                        } else {
                                            System.out.println("Unexpected cmd in active mode: " + line);
                                        }
                                    } else {
                                        System.out.println("Bad convoID - dropping");
                                    }
                                }
                            }
                            break;
                            
                        default:
                            System.out.println("HubStatus in unknown state: " + state);
                            return true;
                    }
                }

                return true;
            }
            
            @Override
            protected void done() {
                try {
                    System.out.println("Done!");
                    get();
                } catch (ExecutionException | InterruptedException e) {
                    e.getCause().printStackTrace();                   
                }
            }
        };

        netlistener.execute();
    }

    /**
     * Gets the SwingWorker thread that is handling network communication. This
     * is so that a main program can use get() to wait on the hub connection
     * to close (by error or normally). This is particularly important for
     * automated programs like chatbots.
     * @return the network listener SwingWorker object
     */
    public SwingWorker getWorkerThread() {
        return netlistener;
    }
    
    /**
     * Request a connection via the chat hub
     * @param convo Conversation object representing this chat
     * @return The Conversation object
     */
    public Conversation connectRequest(Conversation convo) {
        state = STATE_CONNWAIT;
        toHub.println("connect "+convo.getOtherID());
        pendingConn = convo;
        return pendingConn;
    }

    /**
     * Tell chat hub we are dropping this conversation
     * @param convoID ID of conversation to drop
     */
    public void dropConvo(int convoID) {
        toHub.println("drop "+convoID);
        allConvos.remove(convoID);
    }
    
    /**
     * Send a message - called from the Conversation class
     * @param id chat session identifier
     * @param message the message to send
     */
    public void sendMessage(int id, String message) {
        toHub.println("send "+id+" "+message);
    }

    /**
     * Get the LoginCredentials object that was used to set up this session with
     * the chat hub.
     * 
     * @return the login credentials
     */
    public LoginCredentials getLoginCredentials() {
        return credentials;
    }
}