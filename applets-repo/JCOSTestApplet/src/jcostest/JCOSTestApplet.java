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
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.DSAPrivateKey;
import javacard.security.DSAPublicKey;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.Key;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.PrivateKey;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

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
	public static final byte P1_LOAD_FROM_MAIN = (byte) 0x07;
	public static final byte P1_LOAD_FROM_SUB = (byte) 0x08;
	public static final byte KEY_EC_SECP_256_R1 = (byte) 0x01;
	public static final byte KEY_EC_SECP_384_R1 = (byte) 0x02;
	public static final byte KEY_EC_SECP_521_R1 = (byte) 0x03;
	public static final byte KEY_EC_SECP_256_K1 = (byte) 0x04;
	public static final byte KEY_EC_BRAINPOOL_256_R1 = (byte) 0x05;
	public static final byte KEY_EC_BRAINPOOL_384_R1 = (byte) 0x06;
	public static final byte KEY_EC_BRAINPOOL_512_R1 = (byte) 0x07;
	public static final short SW_NOT_SET = (byte) 0x6f11;
	public static final short SW_UNKNOWN_KEY_TYPE = (byte) 0x6fC1;

	private MessageDigest md;
	private Signature signer;
	private Cipher cipher;
	private KeyAgreement ka;
	private Key testKey1;
	private Key testKey2;
	private Key testKey3;
	private Key testKey4;
	private KeyPair testKeyPair1;
	private KeyPair testKeyPair2;
	private byte testKey1Type = (byte) 0x00;
	private byte testKey2Type = (byte) 0x00;
	private byte testKey3Type = (byte) 0x00;
	private byte testKey4Type = (byte) 0x00;
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
			setKey(apdu, buffer);
			break;
		case INS_SET_DATA:
			setData(apdu, buffer);
			break;
		case INS_ENCRYPT:
			encrypt(apdu, buffer);
			break;
		case INS_DECRYPT:
			decrypt(apdu, buffer);
			break;
		case INS_DERIVE:
			derive(apdu, buffer);
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

	public void encrypt(APDU apdu, byte[] buffer) {
		short len = apdu.setIncomingAndReceive();
		byte P1 = buffer[ISO7816.OFFSET_P1];
		byte P2 = buffer[ISO7816.OFFSET_P2];
		switch (P1) {
		case P1_SET:
			try {
				cipher = Cipher.getInstance(P2, false);
			} catch (CryptoException e) {
				ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
			}
			break;
		case P1_IS_SET:
			if (cipher != null) {
				buffer[0] = cipher.getAlgorithm();
				apdu.setOutgoingAndSend((short) 0, (short) 1);
			} else {
				ISOException.throwIt(ISO7816.SW_WARNING_STATE_UNCHANGED);
			}
			break;
		case P1_RESET:
			Key theKey = null;
			if (P2 == (byte) 0x01) {
				theKey = testKey1;
			} else if (P2 == (byte) 0x02) {
				theKey = testKey2;
			} else if (P2 == (byte) 0x03) {
				theKey = testKey3;
			} else if (P2 == (byte) 0x04) {
				theKey = testKey4;
			} else {
				ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
			}
			if (theKey.isInitialized()) {
				cipher.init(theKey, Cipher.MODE_ENCRYPT, buffer, apdu.getOffsetCdata(), len);
			} else {
				ISOException.throwIt(SW_NOT_SET);
			}
			break;
		case P1_UPDATE:
			try {
				short ret = cipher.update(buffer, apdu.getOffsetCdata(), len, b0, (short) 0);
				apdu.setOutgoing();
				apdu.setOutgoingLength(ret);
				apdu.sendBytesLong(b0, (short) 0, ret);
			} catch (CryptoException e) {
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			}
			break;
		case P1_FINAL:
			try {
				short ret = cipher.doFinal(buffer, apdu.getOffsetCdata(), len, b0, (short) 0);
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

	public void decrypt(APDU apdu, byte[] buffer) {
		short len = apdu.setIncomingAndReceive();
		byte P1 = buffer[ISO7816.OFFSET_P1];
		byte P2 = buffer[ISO7816.OFFSET_P2];
		switch (P1) {
		case P1_SET:
			try {
				cipher = Cipher.getInstance(P2, false);
			} catch (CryptoException e) {
				ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
			}
			break;
		case P1_IS_SET:
			if (cipher != null) {
				buffer[0] = cipher.getAlgorithm();
				apdu.setOutgoingAndSend((short) 0, (short) 1);
			} else {
				ISOException.throwIt(ISO7816.SW_WARNING_STATE_UNCHANGED);
			}
			break;
		case P1_RESET:
			Key theKey = null;
			if (P2 == (byte) 0x01) {
				theKey = testKey1;
			} else if (P2 == (byte) 0x02) {
				theKey = testKey2;
			} else if (P2 == (byte) 0x03) {
				theKey = testKey3;
			} else if (P2 == (byte) 0x04) {
				theKey = testKey4;
			} else {
				ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
			}
			if (theKey.isInitialized()) {
				cipher.init(theKey, Cipher.MODE_DECRYPT, buffer, apdu.getOffsetCdata(), len);
			} else {
				ISOException.throwIt(SW_NOT_SET);
			}
			break;
		case P1_UPDATE:
			try {
				short ret = cipher.update(buffer, apdu.getOffsetCdata(), len, b0, (short) 0);
				apdu.setOutgoing();
				apdu.setOutgoingLength(ret);
				apdu.sendBytesLong(b0, (short) 0, ret);
			} catch (CryptoException e) {
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			}
			break;
		case P1_FINAL:
			try {
				short ret = cipher.doFinal(buffer, apdu.getOffsetCdata(), len, b0, (short) 0);
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

	public void derive(APDU apdu, byte[] buffer) {
		short len = apdu.setIncomingAndReceive();
		byte P1 = buffer[ISO7816.OFFSET_P1];
		byte P2 = buffer[ISO7816.OFFSET_P2];
		switch (P1) {
		case P1_SET:
			try {
				ka = KeyAgreement.getInstance(P2, false);
			} catch (CryptoException e) {
				ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
			}
			break;
		case P1_IS_SET:
			if (ka != null) {
				buffer[0] = ka.getAlgorithm();
				apdu.setOutgoingAndSend((short) 0, (short) 1);
			} else {
				ISOException.throwIt(ISO7816.SW_WARNING_STATE_UNCHANGED);
			}
			break;
		case P1_RESET:
			Key theKey = null;
			if (P2 == (byte) 0x01) {
				theKey = testKey1;
			} else if (P2 == (byte) 0x02) {
				theKey = testKey2;
			} else if (P2 == (byte) 0x03) {
				theKey = testKey3;
			} else if (P2 == (byte) 0x04) {
				theKey = testKey4;
			} else {
				ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
			}
			if (theKey.isInitialized()) {
				ka.init((PrivateKey) theKey);
			} else {
				ISOException.throwIt(SW_NOT_SET);
			}
			break;
		case P1_FINAL:
			try {
				short ret = ka.generateSecret(buffer, apdu.getOffsetCdata(), len, b0, (short) 0);
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

	public void sign(APDU apdu, byte[] buffer) {
		short len = apdu.setIncomingAndReceive();
		byte P1 = buffer[ISO7816.OFFSET_P1];
		byte P2 = buffer[ISO7816.OFFSET_P2];
		switch (P1) {
		case P1_SET:
			try {
				signer = Signature.getInstance(P2, false);
			} catch (CryptoException e) {
				ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
			}
			break;
		case P1_IS_SET:
			if (cipher != null) {
				buffer[0] = cipher.getAlgorithm();
				apdu.setOutgoingAndSend((short) 0, (short) 1);
			} else {
				ISOException.throwIt(ISO7816.SW_WARNING_STATE_UNCHANGED);
			}
			break;
		case P1_RESET:
			Key theKey = null;
			if (P2 == (byte) 0x01) {
				theKey = testKey1;
			} else if (P2 == (byte) 0x02) {
				theKey = testKey2;
			} else if (P2 == (byte) 0x03) {
				theKey = testKey3;
			} else if (P2 == (byte) 0x04) {
				theKey = testKey4;
			} else {
				ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
			}
			if (theKey.isInitialized()) {
				if (len == 0) {
					signer.init(theKey, Signature.MODE_SIGN);
				} else {
					signer.init(theKey, Signature.MODE_SIGN, buffer, apdu.getOffsetCdata(), len);
				}
			} else {
				ISOException.throwIt(SW_NOT_SET);
			}
			break;
		case P1_UPDATE:
			try {
				signer.update(buffer, apdu.getOffsetCdata(), len);
			} catch (CryptoException e) {
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			}
			break;
		case P1_FINAL:
			try {
				short ret = signer.sign(buffer, apdu.getOffsetCdata(), len, b0, (short) 0);
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

	public void verify(APDU apdu, byte[] buffer) {
		short len = apdu.setIncomingAndReceive();
		byte P1 = buffer[ISO7816.OFFSET_P1];
		byte P2 = buffer[ISO7816.OFFSET_P2];
		switch (P1) {
		case P1_SET:
			try {
				signer = Signature.getInstance(P2, false);
			} catch (CryptoException e) {
				ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
			}
			break;
		case P1_IS_SET:
			if (cipher != null) {
				buffer[0] = signer.getAlgorithm();
				apdu.setOutgoingAndSend((short) 0, (short) 1);
			} else {
				ISOException.throwIt(ISO7816.SW_WARNING_STATE_UNCHANGED);
			}
			break;
		case P1_RESET:
			Key theKey = null;
			if (P2 == (byte) 0x01) {
				theKey = testKey1;
			} else if (P2 == (byte) 0x02) {
				theKey = testKey2;
			} else if (P2 == (byte) 0x03) {
				theKey = testKey3;
			} else if (P2 == (byte) 0x04) {
				theKey = testKey4;
			} else {
				ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
			}
			if (theKey.isInitialized()) {
				if (len == 0) {
					signer.init(theKey, Signature.MODE_VERIFY);
				} else {
					signer.init(theKey, Signature.MODE_VERIFY, buffer, apdu.getOffsetCdata(), len);
				}
			} else {
				ISOException.throwIt(SW_NOT_SET);
			}
			break;
		case P1_UPDATE:
			try {
				signer.update(buffer, apdu.getOffsetCdata(), len);
			} catch (CryptoException e) {
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			}
			break;
		case P1_FINAL:
			try {
				if (arbitraryData == null) {
					ISOException.throwIt(ISO7816.SW_DATA_INVALID);
				}
				if (signer.verify(arbitraryData, (short) 0, (short) arbitraryData.length, buffer, apdu.getOffsetCdata(), len)) {
					buffer[0] = (byte) 0x01;
				} else {
					buffer[0] = (byte) 0x00;
				}
				apdu.setOutgoingAndSend((short) 0, (short) 1);
			} catch (CryptoException e) {
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			}
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			break;
		}
	}

	public void setKey(APDU apdu, byte[] buffer) {
		short len = apdu.setIncomingAndReceive();
		byte P1 = buffer[ISO7816.OFFSET_P1];
		byte P2 = buffer[ISO7816.OFFSET_P2];
		Key theKey = null;
		byte theKeyType = (byte) 0x00;
		switch (P1) {
		case P1_SET:
			if (len != 3) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}

			len = Util.makeShort(buffer[apdu.getOffsetCdata()], buffer[(short) (apdu.getOffsetCdata() + 1)]);

			if (P2 == (byte) 0x01) {
				testKey1.clearKey();
				testKey1 = KeyBuilder.buildKey(P2, len, false);
				testKey1Type = buffer[(short) (apdu.getOffsetCdata() + 2)];
			} else if (P2 == (byte) 0x02) {
				testKey2.clearKey();
				testKey2 = KeyBuilder.buildKey(P2, len, false);
				testKey2Type = buffer[(short) (apdu.getOffsetCdata() + 2)];
			} else if (P2 == (byte) 0x03) {
				testKey3.clearKey();
				testKey3 = KeyBuilder.buildKey(P2, len, false);
				testKey3Type = buffer[(short) (apdu.getOffsetCdata() + 2)];
			} else if (P2 == (byte) 0x04) {
				testKey4.clearKey();
				testKey4 = KeyBuilder.buildKey(P2, len, false);
				testKey4Type = buffer[(short) (apdu.getOffsetCdata() + 2)];
			} else {
				ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
			}
			break;
		case P1_LOAD_FROM_MAIN:
			// Set from main applet
			if (P2 == (byte) 0x01) {
				theKey = testKey1;
				theKeyType = testKey1Type;
			} else if (P2 == (byte) 0x02) {
				theKey = testKey2;
				theKeyType = testKey2Type;
			} else if (P2 == (byte) 0x03) {
				theKey = testKey3;
				theKeyType = testKey3Type;
			} else if (P2 == (byte) 0x04) {
				theKey = testKey4;
				theKeyType = testKey4Type;
			} else {
				ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
			}
			if (theKey == null) {
				ISOException.throwIt(SW_NOT_SET);
			}
			setKey(theKey, theKeyType, buffer, apdu.getOffsetCdata(), len);
			break;
		case P1_LOAD_FROM_SUB:
			// Set from alternate static class
			if (P2 == (byte) 0x01) {
				theKey = testKey1;
				theKeyType = testKey1Type;
			} else if (P2 == (byte) 0x02) {
				theKey = testKey2;
				theKeyType = testKey2Type;
			} else if (P2 == (byte) 0x03) {
				theKey = testKey3;
				theKeyType = testKey3Type;
			} else if (P2 == (byte) 0x04) {
				theKey = testKey4;
				theKeyType = testKey4Type;
			} else {
				ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
			}
			if (theKey == null) {
				ISOException.throwIt(SW_NOT_SET);
			}
			AlternateKM.setKey(theKey, theKeyType, buffer, apdu.getOffsetCdata(), len);
			break;
		case P1_GET:
			if (P2 == (byte) 0x01) {
				theKey = testKey1;
			} else if (P2 == (byte) 0x02) {
				theKey = testKey2;
			} else if (P2 == (byte) 0x03) {
				theKey = testKey3;
			} else if (P2 == (byte) 0x04) {
				theKey = testKey4;
			} else {
				ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
			}
			if (!theKey.isInitialized()) {
				ISOException.throwIt(SW_NOT_SET);
			}
			if (theKey instanceof AESKey) {
				len = ((AESKey) theKey).getKey(buffer, (short) 0);
			} else if (theKey instanceof DESKey) {
				len = ((DESKey) theKey).getKey(buffer, (short) 0);
			} else if (theKey instanceof DSAPublicKey) {
				len = ((DSAPublicKey) theKey).getY(buffer, (short) 0);
			} else if (theKey instanceof DSAPrivateKey) {
				len = ((DSAPrivateKey) theKey).getX(buffer, (short) 0);
			} else if (theKey instanceof ECPublicKey) {
				len = ((ECPublicKey) theKey).getW(buffer, (short) 0);
			} else if (theKey instanceof ECPrivateKey) {
				len = ((ECPrivateKey) theKey).getS(buffer, (short) 0);
			} else if (theKey instanceof RSAPublicKey) {
				if (len == 1) {
					if (buffer[apdu.getOffsetCdata()] == (byte) 0x00) {
						len = ((RSAPublicKey) theKey).getModulus(buffer, (short) 0);
					} else {
						len = ((RSAPublicKey) theKey).getExponent(buffer, (short) 0);
					}
				} else {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
			} else if (theKey instanceof RSAPrivateKey) {
				if (len == 1) {
					if (buffer[apdu.getOffsetCdata()] == (byte) 0x00) {
						len = ((RSAPrivateKey) theKey).getModulus(buffer, (short) 0);
					} else {
						len = ((RSAPrivateKey) theKey).getExponent(buffer, (short) 0);
					}
				} else {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
			} else {
				ISOException.throwIt(SW_UNKNOWN_KEY_TYPE);
			}
			apdu.setOutgoingAndSend((short) 0, len);
			break;
		case P1_IS_SET:
			if (P2 == (byte) 0x01) {
				theKey = testKey1;
			} else if (P2 == (byte) 0x02) {
				theKey = testKey2;
			} else if (P2 == (byte) 0x03) {
				theKey = testKey3;
			} else if (P2 == (byte) 0x04) {
				theKey = testKey4;
			} else {
				ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
			}
			if (!theKey.isInitialized()) {
				ISOException.throwIt(SW_NOT_SET);
			}
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
		case P1_LOAD_FROM_MAIN:
			// Set from main applet
			if (len <= 0) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
			arbitraryData = null;
			arbitraryData = new byte[len];
			Util.arrayCopy(buffer, apdu.getOffsetCdata(), arbitraryData, (short) 0, len);
			break;
		case P1_LOAD_FROM_SUB:
			// Set from alternate class
			if (len <= 0) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
			arbitraryData = null;
			arbitraryData = new byte[len];
			AlternateKM.setData(buffer, apdu.getOffsetCdata(), arbitraryData, (short) 0, len);
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

	public boolean setKey(Key key, byte keyType, byte[] keyData, short kOff, short kLen) {
		if (key instanceof AESKey) {
			((AESKey) key).setKey(keyData, kOff);
		} else if (key instanceof DESKey) {
			((DESKey) key).setKey(keyData, kOff);
//		} else if (key instanceof DSAPublicKey) {
//			((DSAPublicKey) key).setG(paramData, off[0], len[0]);
//			((DSAPublicKey) key).setP(paramData, off[1], len[1]);
//			((DSAPublicKey) key).setQ(paramData, off[2], len[2]);
//			((DSAPublicKey) key).setY(keyData, off[3], len[3]);
//		} else if (key instanceof DSAPrivateKey) {
//			((DSAPrivateKey) key).setG(paramData, off[0], len[0]);
//			((DSAPrivateKey) key).setP(paramData, off[1], len[1]);
//			((DSAPrivateKey) key).setQ(paramData, off[2], len[2]);
//			((DSAPrivateKey) key).setX(keyData, off[3], len[3]);
		} else if (key instanceof ECPublicKey) {
			initECCurveParameters(key, keyType);
			((ECPublicKey) key).setW(keyData, kOff, kLen);
		} else if (key instanceof ECPrivateKey) {
			initECCurveParameters(key, keyType);
			((ECPrivateKey) key).setS(keyData, kOff, kLen);
//		} else if (key instanceof RSAPublicKey) {
//			((RSAPublicKey) key).setModulus(keyData, off[0], len[0]);
//			((RSAPublicKey) key).setExponent(keyData, off[1], len[1]);
//		} else if (key instanceof RSAPrivateKey) {
//			((RSAPrivateKey) key).setModulus(keyData, off[0], len[0]);
//			((RSAPrivateKey) key).setExponent(keyData, off[1], len[1]);
		} else {
			return false;
		}
		return true;
	}

	public void initECCurveParameters(Key key, byte keyType) {
		if (keyType == KEY_EC_SECP_256_R1) {
			((ECKey) key).setA(Constants.ansix9p256r1_a, (short) 0, (short) Constants.ansix9p256r1_a.length);
			((ECKey) key).setB(Constants.ansix9p256r1_b, (short) 0, (short) Constants.ansix9p256r1_b.length);
			((ECKey) key).setFieldFP(Constants.ansix9p256r1_field, (short) 0,
					(short) Constants.ansix9p256r1_field.length);
			((ECKey) key).setG(Constants.ansix9p256r1_g, (short) 0, (short) Constants.ansix9p256r1_g.length);
			((ECKey) key).setR(Constants.ansix9p256r1_r, (short) 0, (short) Constants.ansix9p256r1_r.length);
			((ECKey) key).setK((short) 1);
		} else if (keyType == KEY_EC_SECP_384_R1) {
			((ECKey) key).setA(Constants.ansix9p384r1_a, (short) 0, (short) Constants.ansix9p384r1_a.length);
			((ECKey) key).setB(Constants.ansix9p384r1_b, (short) 0, (short) Constants.ansix9p384r1_b.length);
			((ECKey) key).setFieldFP(Constants.ansix9p384r1_field, (short) 0,
					(short) Constants.ansix9p384r1_field.length);
			((ECKey) key).setG(Constants.ansix9p384r1_g, (short) 0, (short) Constants.ansix9p384r1_g.length);
			((ECKey) key).setR(Constants.ansix9p384r1_r, (short) 0, (short) Constants.ansix9p384r1_r.length);
			((ECKey) key).setK((short) 1);
		} else if (keyType == KEY_EC_SECP_521_R1) {
			((ECKey) key).setA(Constants.ansix9p521r1_a, (short) 0, (short) Constants.ansix9p521r1_a.length);
			((ECKey) key).setB(Constants.ansix9p521r1_b, (short) 0, (short) Constants.ansix9p521r1_b.length);
			((ECKey) key).setFieldFP(Constants.ansix9p521r1_field, (short) 0,
					(short) Constants.ansix9p521r1_field.length);
			((ECKey) key).setG(Constants.ansix9p521r1_g, (short) 0, (short) Constants.ansix9p521r1_g.length);
			((ECKey) key).setR(Constants.ansix9p521r1_r, (short) 0, (short) Constants.ansix9p521r1_r.length);
			((ECKey) key).setK((short) 1);
		} else if (keyType == KEY_EC_SECP_256_K1) {
			((ECKey) key).setA(Constants.SECP256K1_A, (short) 0, (short) Constants.SECP256K1_A.length);
			((ECKey) key).setB(Constants.SECP256K1_B, (short) 0, (short) Constants.SECP256K1_B.length);
			((ECKey) key).setFieldFP(Constants.SECP256K1_FIELD, (short) 0, (short) Constants.SECP256K1_FIELD.length);
			((ECKey) key).setG(Constants.SECP256K1_G, (short) 0, (short) Constants.SECP256K1_G.length);
			((ECKey) key).setR(Constants.SECP256K1_R, (short) 0, (short) Constants.SECP256K1_R.length);
			((ECKey) key).setK((short) 1);
		} else if (keyType == KEY_EC_BRAINPOOL_256_R1) {
			((ECKey) key).setA(Constants.brainpoolP256r1_a, (short) 0, (short) Constants.brainpoolP256r1_a.length);
			((ECKey) key).setB(Constants.brainpoolP256r1_b, (short) 0, (short) Constants.brainpoolP256r1_b.length);
			((ECKey) key).setFieldFP(Constants.brainpoolP256r1_field, (short) 0,
					(short) Constants.brainpoolP256r1_field.length);
			((ECKey) key).setG(Constants.brainpoolP256r1_g, (short) 0, (short) Constants.brainpoolP256r1_g.length);
			((ECKey) key).setR(Constants.brainpoolP256r1_r, (short) 0, (short) Constants.brainpoolP256r1_r.length);
			((ECKey) key).setK((short) 1);
		} else if (keyType == KEY_EC_BRAINPOOL_384_R1) {
			((ECKey) key).setA(Constants.brainpoolP384r1_a, (short) 0, (short) Constants.brainpoolP384r1_a.length);
			((ECKey) key).setB(Constants.brainpoolP384r1_b, (short) 0, (short) Constants.brainpoolP384r1_b.length);
			((ECKey) key).setFieldFP(Constants.brainpoolP384r1_field, (short) 0,
					(short) Constants.brainpoolP384r1_field.length);
			((ECKey) key).setG(Constants.brainpoolP384r1_g, (short) 0, (short) Constants.brainpoolP384r1_g.length);
			((ECKey) key).setR(Constants.brainpoolP384r1_r, (short) 0, (short) Constants.brainpoolP384r1_r.length);
			((ECKey) key).setK((short) 1);
		} else if (keyType == KEY_EC_BRAINPOOL_512_R1) {
			((ECKey) key).setA(Constants.brainpoolP512r1_a, (short) 0, (short) Constants.brainpoolP512r1_a.length);
			((ECKey) key).setB(Constants.brainpoolP512r1_b, (short) 0, (short) Constants.brainpoolP512r1_b.length);
			((ECKey) key).setFieldFP(Constants.brainpoolP512r1_field, (short) 0,
					(short) Constants.brainpoolP512r1_field.length);
			((ECKey) key).setG(Constants.brainpoolP512r1_g, (short) 0, (short) Constants.brainpoolP512r1_g.length);
			((ECKey) key).setR(Constants.brainpoolP512r1_r, (short) 0, (short) Constants.brainpoolP512r1_r.length);
			((ECKey) key).setK((short) 1);
		}
	}
}
