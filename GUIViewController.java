/**
 * The generic view "glue" that is used for a GUI interface
 */
public class GUIViewController implements ChatViewController {
    public GUIViewController() {
    }

    class GUIView implements ChatView {
        SimpleChatUI gui;
        
        public GUIView(Conversation convo) {
            gui = SimpleChatUI.connectWindow(convo);
        }

        @Override
        public void setConnStatus(boolean connected) {
            gui.setConnStatus(connected);
        }

        @Override
        public void addInfoMessage(String info) {
            gui.addToChatWindow(info);
        }
//getOtherInfo
        @Override
        public void addReceivedMessage(Conversation convo, String msg) {
            gui.addToChatWindow(convo.getOtherID()+": "+msg);
        }

        @Override
        public void disconnectConvo() {
            gui.disconnectConvo();
        }
    }
    
    public ChatView newView(Conversation convo) {
        return new GUIView(convo);       
    }
}
