/**
 * This interface represents a manager for different chat views (e.g., a GUI,
 * or a text-based interface, or a chatbot view, or...)
 * 
 * @version 0.1
 * @author srt
 */
interface ChatViewController {
    public ChatView newView(Conversation convo);
}
