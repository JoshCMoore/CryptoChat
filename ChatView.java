/**
 * An individual chat conversation view (user interface or automated chatbot)
 * 
 * @version 0.1
 * @author srt
 */
public interface ChatView {

    /**
     * Update the connected/disconnected status in the view.
     * @param connected true if connected, false if not connected
     */
    public void setConnStatus(boolean connected);

    /**
     * Add an informational message to the view. This is primarily intended
     * for informational messages for a human user, and would generally be
     * ignored by automated chatbot views.
     * @param info the informational message
     */
    public void addInfoMessage(String info);

    /**
     * Send a received message along to the view for display/processing.
     * @param convo the conversation that the message is a part of
     * @param msg the message
     */
    public void addReceivedMessage(Conversation convo, String msg);

    /**
     * A conversation is ending, so disconnect the view.
     */
    public void disconnectConvo();
}
