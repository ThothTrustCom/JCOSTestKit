package org.thothtrust.jcostest.sc;

import java.util.ArrayList;
import java.util.List;
import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;

import interfaces.TestDevice;

/**
 *
 * @author ThothTrust Pte Ltd.
 */
public class DeviceManager {

	private static DeviceManager instance = null;
	private TerminalHandler termMan = null;
	public static final String DEFAULT_CARD_PROTO = TerminalHandler.CARD_PROTO_T_0;
	private ArrayList<TestDevice> devices = new ArrayList<>();
	private byte[] aid = { (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55 };

	protected DeviceManager() throws CardException {
		termMan = new TerminalHandler();
		refreshDevices();
	}

	public static DeviceManager getInstance() throws CardException {
		if (instance == null) {
			instance = new DeviceManager();
		}

		return instance;
	}
	
	public void refreshDevices() throws CardException {
		disconnectAllExistingDevices();
		termMan.loadDefaultTerminal();
		devices.clear();
		List<CardTerminal> terminals = termMan.getTerminals();
		for (int i = 0; i < terminals.size(); i++) {
			Card tempCard = termMan.getCard(DEFAULT_CARD_PROTO, i);
			TestDevice tempDevice = new TestDevice(tempCard, terminals.get(i).getName());
			if (tempDevice.connect(aid)) {
				devices.add(tempDevice);
			}
		}
	}

	public void disconnectAllExistingDevices() throws CardException {
		if (devices.size() > 0) {
			for (TestDevice tempDevice : devices) {
				tempDevice.disconnect();
			}
		}
	}

	public int getDevicesCount() {
		return devices.size();
	}

	public ArrayList<TestDevice> getDevices() {
		return devices;
	}
	
	public TestDevice getDevice(int i) {
		return devices.get(i);
	}

	public byte[] getAid() {
		return aid;
	}

	public void setAid(byte[] aid) {
		this.aid = aid;
	}
}
