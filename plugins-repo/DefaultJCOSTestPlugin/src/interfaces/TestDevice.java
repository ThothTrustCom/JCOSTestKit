package interfaces;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 *
 * @author ThothTrust Pte Ltd.
 */
public class TestDevice {

    private Card card = null;
    private CardChannel channel = null;

    private String terminalName = null;

    public TestDevice(Card card, String terminalName) {
        if ((card != null) && (terminalName != null)) {
            setCard(card);
            setTerminalName(terminalName);
        }
    }

    public boolean connect(byte[] aid) throws CardException {
        if (card != null) {
            setChannel(getCard().getBasicChannel());
        }
        return checkCard(aid);
    }

    public void disconnect() throws CardException {
        if (card != null) {
            card.disconnect(true);
            card = null;
            channel = null;
        }
    }

    public boolean checkCard(byte[] aid) throws CardException {
        if (channel != null) {
            // Query THETACore Applet
            CommandAPDU cmd = null;
            
            cmd = new CommandAPDU(Constants.APDU_SELECT[0], Constants.APDU_SELECT[1], Constants.APDU_SELECT[2], Constants.APDU_SELECT[2], aid);
            ResponseAPDU selectResponse = send(cmd);
            
            return DeviceHelper.isSuccessfulResponse(selectResponse);
        }

        return false;
    }

    public byte[] getATRBytes() {
        return card.getATR().getBytes();
    }

    public ResponseAPDU send(CommandAPDU message) throws CardException {
        if (channel != null) {
            return channel.transmit(message);
        }

        return null;
    }

    /**
     * @return the card
     */
    public Card getCard() {
        return card;
    }

    /**
     * @param card the card to set
     */
    private void setCard(Card card) {
        this.card = card;
    }

    /**
     * @return the channel
     */
    public CardChannel getChannel() {
        return channel;
    }

    /**
     * @param channel the channel to set
     */
    private void setChannel(CardChannel channel) {
        this.channel = channel;
    }

    /**
     * @return the terminalName
     */
    public String getTerminalName() {
        return terminalName;
    }

    /**
     * @param terminalName the terminalName to set
     */
    private void setTerminalName(String terminalName) {
        this.terminalName = terminalName;
    }

}
