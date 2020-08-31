/**
 * The 3-Clause BSD License
 * 
 * Copyright 2020 ThothTrust Pte Ltd.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are 
 * permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this list 
 * 	  of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice, this 
 * 	  list of conditions and the following disclaimer in the documentation and/or other 
 *    materials provided with the distribution.
 *    
 * 3. Neither the name of the copyright holder nor the names of its contributors may be 
 *    used to endorse or promote products derived from this software without specific 
 *    prior written permission.
 *    
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY 
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES 
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
 * SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED 
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR 
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN 
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH 
 * DAMAGE.
 */

package jcostest;

import javacard.framework.*;
import javacard.security.CryptoException;
import javacard.security.Key;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.Signature;

/**
 * Applet class
 * 
 * @author ThothTrust Pte Ltd.
 */
public class JCOSTestApplet extends Applet {

	public static final byte INS_SET_KEY = (byte) 0x01;
	public static final byte INS_SET_DATA = (byte) 0x02;
	public static final byte INS_ENCRYPT = (byte) 0x03;
	public static final byte INS_DECRYPT = (byte) 0x04;
	public static final byte INS_DERIVE = (byte) 0x05;
	public static final byte INS_HASH = (byte) 0x06;
	public static final byte INS_SIGN = (byte) 0x07;
	public static final byte INS_VERIFY = (byte) 0x08;
	public static final byte P1_SET = (byte) 0x01;
	public static final byte P1_GET = (byte) 0x02;
	public static final byte P1_IS_SET = (byte) 0x03;
	public static final byte P1_RESET = (byte) 0x04;
	public static final byte P1_UPDATE = (byte) 0x05;
	public static final byte P1_FINAL = (byte) 0x06;
	public static final byte P2_PART_MAIN = (byte) 0x01;
	public static final byte P2_PART_SUB = (byte) 0x02;

	private MessageDigest md;
	private Signature signer;
	private Key testKey1;
	private Key testKey2;
	private Key testKey3;
	private Key testKey4;
	private KeyPair testKeyPair1;
	private KeyPair testKeyPair2;
	public byte[] arbitraryData = null;
	private byte[] b0 = JCSystem.makeTransientByteArray((short) 100, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new JCOSTestApplet();
	}

	protected JCOSTestApplet() {
		register();
	}

	public void process(APDU apdu) {
		if (selectingApplet()) {
			return;
		}

		final byte[] buffer = apdu.getBuffer();
		final byte ins = buffer[ISO7816.OFFSET_INS];
		short len = 0;

		switch (ins) {
		case INS_SET_KEY:
			break;
		case INS_SET_DATA:
			setData(apdu, buffer);
			break;
		case INS_ENCRYPT:
			break;
		case INS_DECRYPT:
			break;
		case INS_DERIVE:
			break;
		case INS_HASH:
			doHash(apdu, buffer);
			break;
		case INS_SIGN:
			break;
		case INS_VERIFY:
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			break;
		}
	}

	public void setKey(APDU apdu, byte[] buffer) {
		short len = apdu.setIncomingAndReceive();
		byte P1 = buffer[ISO7816.OFFSET_P1];
		byte P2 = buffer[ISO7816.OFFSET_P2];
		switch (P1) {
		case P1_SET:
			if (P2 == P2_PART_MAIN) {
				// TODO: Set from main applet
			} else if (P2 == P2_PART_SUB) {
				// Set from alternate class
				// Currently only sets ECC P256R1 and ECC BrainPool256R1
			}
			break;
		case P1_GET:

			break;
		case P1_IS_SET:

			break;
		default:
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			break;
		}
	}

	public void setData(APDU apdu, byte[] buffer) {
		short len = apdu.setIncomingAndReceive();
		byte P1 = buffer[ISO7816.OFFSET_P1];
		byte P2 = buffer[ISO7816.OFFSET_P2];
		switch (P1) {
		case P1_SET:
			if (P2 == P2_PART_MAIN) {
				// TODO: Set from main applet
			} else if (P2 == P2_PART_SUB) {
				// Set from alternate class
				if (len <= 0) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
				arbitraryData = null;
				arbitraryData = new byte[len];
				AlternateKM.setData(buffer, apdu.getOffsetCdata(), arbitraryData, (short) 0, len);
			}
			break;
		case P1_GET:
			if (len != 4) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
			short getOff = Util.makeShort(buffer[apdu.getOffsetCdata()], buffer[(short) (apdu.getOffsetCdata() + 1)]);
			short getLen = Util.makeShort(buffer[(short) (apdu.getOffsetCdata() + 2)],
					buffer[(short) (apdu.getOffsetCdata() + 3)]);
			Util.arrayCopyNonAtomic(arbitraryData, getOff, buffer, (short) 0, getLen);
			apdu.setOutgoingAndSend((short) 0, getLen);
			break;
		case P1_IS_SET:
			if (arbitraryData == null) {
				ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
			} else {
				Util.setShort(buffer, (short) 0, (short) arbitraryData.length);
				apdu.setOutgoingAndSend((short) 0, (short) 2);
			}
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			break;
		}
	}

	public void doHash(APDU apdu, byte[] buffer) {
		short len = apdu.setIncomingAndReceive();
		byte P1 = buffer[ISO7816.OFFSET_P1];
		byte P2 = buffer[ISO7816.OFFSET_P2];
		switch (P1) {
		case P1_SET:
			try {
				md = MessageDigest.getInstance(P2, false);
			} catch (CryptoException e) {
				ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
			}
			break;
		case P1_IS_SET:
			if (md != null) {
				buffer[0] = md.getAlgorithm();
				apdu.setOutgoingAndSend((short) 0, (short) 1);
			} else {
				ISOException.throwIt(ISO7816.SW_WARNING_STATE_UNCHANGED);
			}
			break;
		case P1_RESET:
			md.reset();
			break;
		case P1_UPDATE:
			try {
				md.update(buffer, apdu.getOffsetCdata(), len);
			} catch (CryptoException e) {
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			}
			break;
		case P1_FINAL:
			try {
				short ret = md.doFinal(buffer, apdu.getOffsetCdata(), len, b0, (short) 0);
				apdu.setOutgoing();
				apdu.setOutgoingLength(ret);
				apdu.sendBytesLong(b0, (short) 0, ret);
			} catch (CryptoException e) {
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			}
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			break;
		}
	}
}
