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
 * @contributors Christian Kahlo, Razvan Dragomirescu.
 */
public class JCOSTestApplet extends Applet {

	public static final byte INS_SET_KEY = (byte) 0x01;
	public static final byte INS_SET_DATA = (byte) 0x02;
	public static final byte INS_GET_KEY = (byte) 0x03;
	public static final byte INS_GET_DATA = (byte) 0x04;
	public static final byte INS_ENCRYPT = (byte) 0x05;
	public static final byte INS_DECRYPT = (byte) 0x06;
	public static final byte INS_DERIVE = (byte) 0x07;
	public static final byte INS_HASH = (byte) 0x08;
	public static final byte INS_SIGN = (byte) 0x09;
	public static final byte INS_VERIFY = (byte) 0x0A;
	public static final byte INS_JAVA = (byte) 0x0B;
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
	public static final short SW_NOT_SET = (short) 0x6fC1;
	public static final short SW_FAILED_SET = (short) 0x6fC2;
	public static final short SW_UNKNOWN_KEY_TYPE = (short) 0x6fC3;

	private MessageDigest md = null;
	private Signature signer = null;
	private Cipher cipher = null;
	private KeyAgreement ka = null;
	private Key testKey1 = null;
	private Key testKey2 = null;
	private Key testKey3 = null;
	private Key testKey4 = null;
	private KeyPair testKeyPair1 = null;
	private KeyPair testKeyPair2 = null;
	private byte testKey1Type = (byte) 0x00;
	private byte testKey2Type = (byte) 0x00;
	private byte testKey3Type = (byte) 0x00;
	private byte testKey4Type = (byte) 0x00;
	private byte testKey1PersistentType = (byte) 0x00;
	private byte testKey2PersistentType = (byte) 0x00;
	private byte testKey3PersistentType = (byte) 0x00;
	private byte testKey4PersistentType = (byte) 0x00;
	public byte[] arbitraryData = null;
	private byte[] b0 = JCSystem.makeTransientByteArray((short) 256, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
	private byte[] b1 = JCSystem.makeTransientByteArray((short) 255, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);

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

		switch (ins) {
		case INS_SET_KEY:
			setKey(apdu, buffer);
			break;
		case INS_SET_DATA:
			setData(apdu, buffer);
			break;
		case INS_GET_KEY:
			short ret = 0;
			byte P2 = buffer[ISO7816.OFFSET_P2];
			if (P2 == (byte) 0x01) {
				ret = getKey(testKey1, testKey1PersistentType, buffer, (short) 0);
			} else if (P2 == (byte) 0x02) {
				ret = getKey(testKey2, testKey2PersistentType, buffer, (short) 0);
			} else if (P2 == (byte) 0x03) {
				ret = getKey(testKey3, testKey3PersistentType, buffer, (short) 0);
			} else if (P2 == (byte) 0x04) {
				ret = getKey(testKey4, testKey4PersistentType, buffer, (short) 0);
			} else {
				ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
			}
			apdu.setOutgoingAndSend((short) 0, ret);
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
			sign(apdu, buffer);
			break;
		case INS_VERIFY:
			verify(apdu, buffer);
			break;
		case INS_JAVA:
			javaVMTests(apdu, buffer);
			break;
		case (byte) 0xF0:
			getKeyInstance(testKey1);
			break;
		case (byte) 0xF1:
			getCipherInstance();
			break;
		case (byte) 0xF2:
			getSignerInstance();
			break;
		case (byte) 0xF3:
			getKeyAgreementInstance();
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			break;
		}
	}

	public void javaVMTests(APDU apdu, byte[] buffer) {
		byte P1 = buffer[ISO7816.OFFSET_P1];
		byte P2 = buffer[ISO7816.OFFSET_P2];
		switch (P1) {
		case (byte) 0x01:
			buffer[0] = javaInstanceOfTest();
			apdu.setOutgoingAndSend((short) 0, (short) 1);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			break;
		}
	}

	/**
	 * Tests instanceof for proper type matching.
	 * 
	 * Thanks to <a href="https://github.com/ckahlo">ckhalo</a> for pointing out
	 * this issue on existing JavaCards.
	 * 
	 * @return matched byte if key type.
	 */
	public byte javaInstanceOfTest() {
		if (testKey4 != null) {
			testKey4.clearKey();
		}
		testKey4 = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
		testKey4Type = (byte) 0x00;

		if (testKey4 instanceof DESKey) {
			return (byte) 0x01;
		} else if (testKey4 instanceof AESKey) {
			return (byte) 0x02;
		} else if (testKey4 instanceof RSAPrivateKey) {
			return (byte) 0x03;
		} else if (testKey4 instanceof RSAPublicKey) {
			return (byte) 0x04;
		} else if (testKey4 instanceof ECPrivateKey) {
			return (byte) 0x05;
		} else if (testKey4 instanceof ECPublicKey) {
			return (byte) 0x06;
		}
		return (byte) 0xFF;
	}

	public Key buildPreciseKey(Key key, byte keyPersistenceType, short keyLength) {
		switch (keyPersistenceType) {
		case KeyBuilder.TYPE_AES:
			key = (AESKey) KeyBuilder.buildKey(keyPersistenceType, keyLength, false);
			break;
		case KeyBuilder.TYPE_AES_TRANSIENT_DESELECT:
			key = (AESKey) KeyBuilder.buildKey(keyPersistenceType, keyLength, false);
			break;
		case KeyBuilder.TYPE_AES_TRANSIENT_RESET:
			key = (AESKey) KeyBuilder.buildKey(keyPersistenceType, keyLength, false);
			break;
		case KeyBuilder.TYPE_DES:
			key = (DESKey) KeyBuilder.buildKey(keyPersistenceType, keyLength, false);
			break;
		case KeyBuilder.TYPE_DES_TRANSIENT_DESELECT:
			key = (DESKey) KeyBuilder.buildKey(keyPersistenceType, keyLength, false);
			break;
		case KeyBuilder.TYPE_DES_TRANSIENT_RESET:
			key = (DESKey) KeyBuilder.buildKey(keyPersistenceType, keyLength, false);
			break;
		case KeyBuilder.TYPE_EC_FP_PRIVATE:
			key = (ECPrivateKey) KeyBuilder.buildKey(keyPersistenceType, keyLength, false);
			break;
		case KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT:
			key = (ECPrivateKey) KeyBuilder.buildKey(keyPersistenceType, keyLength, false);
			break;
		case KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_RESET:
			key = (ECPrivateKey) KeyBuilder.buildKey(keyPersistenceType, keyLength, false);
			break;
		case KeyBuilder.TYPE_EC_FP_PUBLIC:
			key = (ECPublicKey) KeyBuilder.buildKey(keyPersistenceType, keyLength, false);
			break;
		default:
			break;
		}
		if (key == null) {
			ISOException.throwIt(ISO7816.SW_WARNING_STATE_UNCHANGED);
		}
		return key;
	}

	public short getKey(Key key, byte keyPersistenceType, byte[] output, short outOff) {
		short ret = 0;
		if (testKey1 == null) {
			ISOException.throwIt(SW_NOT_SET);
		}
		if (!testKey1.isInitialized()) {
			ISOException.throwIt(SW_NOT_SET);
		}
		switch (keyPersistenceType) {
		case KeyBuilder.TYPE_AES:
			ret = ((AESKey) key).getKey(output, outOff);
			break;
		case KeyBuilder.TYPE_AES_TRANSIENT_DESELECT:
			ret = ((AESKey) key).getKey(output, outOff);
			break;
		case KeyBuilder.TYPE_AES_TRANSIENT_RESET:
			ret = ((AESKey) key).getKey(output, outOff);
			break;
		case KeyBuilder.TYPE_DES:
			ret = ((DESKey) key).getKey(output, outOff);
			break;
		case KeyBuilder.TYPE_DES_TRANSIENT_DESELECT:
			ret = ((DESKey) key).getKey(output, outOff);
			break;
		case KeyBuilder.TYPE_DES_TRANSIENT_RESET:
			ret = ((DESKey) key).getKey(output, outOff);
			break;
		case KeyBuilder.TYPE_EC_FP_PRIVATE:
			ret = ((ECPrivateKey) key).getS(output, outOff);
			break;
		case KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT:
			ret = ((ECPrivateKey) key).getS(output, outOff);
			break;
		case KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_RESET:
			ret = ((ECPrivateKey) key).getS(output, outOff);
			break;
		case KeyBuilder.TYPE_EC_FP_PUBLIC:
			ret = ((ECPublicKey) key).getW(output, outOff);
			break;
		default:
			break;
		}
		return ret;
	}
	
	public void getKeyInstance(Key key) {
		if (testKey1 == null) {
			ISOException.throwIt(SW_NOT_SET);
		}
		if (!testKey1.isInitialized()) {
			ISOException.throwIt(SW_NOT_SET);
		}
		if (key instanceof AESKey) {
			ISOException.throwIt(Util.makeShort((byte) 0x6a, (byte) 0xe1));
		} else if (key instanceof DESKey) {
			ISOException.throwIt(Util.makeShort((byte) 0x6a, (byte) 0xe2));
		} else if (key instanceof RSAPrivateKey) {
			ISOException.throwIt(Util.makeShort((byte) 0x6a, (byte) 0xe3));
		} else if (key instanceof RSAPublicKey) {
			ISOException.throwIt(Util.makeShort((byte) 0x6a, (byte) 0xe4));
		} else if (key instanceof ECPrivateKey) {
			ISOException.throwIt(Util.makeShort((byte) 0x6a, (byte) 0xe5));
		} else if (key instanceof ECPublicKey) {
			ISOException.throwIt(Util.makeShort((byte) 0x6a, (byte) 0xe6));
		} else {
			ISOException.throwIt(Util.makeShort((byte) 0x6a, (byte) 0xff));
		}
	}
	
	public void getCipherInstance() {
		if (cipher == null) {
			ISOException.throwIt(SW_NOT_SET);
		}
		ISOException.throwIt(Util.makeShort((byte) 0x6a, cipher.getAlgorithm()));
	}
	
	public void getSignerInstance() {
		if (signer == null) {
			ISOException.throwIt(SW_NOT_SET);
		}
		ISOException.throwIt(Util.makeShort((byte) 0x6a, signer.getAlgorithm()));
	}
	
	public void getKeyAgreementInstance() {
		if (ka == null) {
			ISOException.throwIt(SW_NOT_SET);
		}
		ISOException.throwIt(Util.makeShort((byte) 0x6a, ka.getAlgorithm()));
	}

	/**
	 * Tests of key setting using setting key parameters from main Applet class and
	 * from a secondary separate static class.
	 * 
	 * Thanks to <a href="https://github.com/ckahlo">ckhalo</a> for pointing out
	 * this issue for initializing key parameters from separate static class.
	 * 
	 * @return matched byte if key type.
	 */
	public void setKey(APDU apdu, byte[] buffer) {
		short len = apdu.setIncomingAndReceive();
		byte P1 = buffer[ISO7816.OFFSET_P1];
		byte P2 = buffer[ISO7816.OFFSET_P2];
//		Key theKey = null;
//		byte theKeyType = (byte) 0x00;
		switch (P1) {
		case P1_SET:
			if (len != 4) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}

			len = Util.makeShort(buffer[apdu.getOffsetCdata()], buffer[(short) (apdu.getOffsetCdata() + 1)]);
			Util.arrayFillNonAtomic(b0, (short) 0, (short) b0.length, (byte) 0x00);

			if (P2 == (byte) 0x01) {
				if (testKey1 != null) {
					testKey1.clearKey();
				}
				testKey1PersistentType = buffer[(short) (apdu.getOffsetCdata() + 3)];
				testKey1 = buildPreciseKey(testKey1, testKey1PersistentType, len);
				testKey1Type = buffer[(short) (apdu.getOffsetCdata() + 2)];
			} else if (P2 == (byte) 0x02) {
				if (testKey2 != null) {
					testKey2.clearKey();
				}
				testKey2PersistentType = buffer[(short) (apdu.getOffsetCdata() + 3)];
				testKey2 = buildPreciseKey(testKey2, testKey2PersistentType, len);
				testKey2Type = buffer[(short) (apdu.getOffsetCdata() + 2)];
			} else if (P2 == (byte) 0x03) {
				if (testKey3 != null) {
					testKey3.clearKey();
				}
				testKey3PersistentType = buffer[(short) (apdu.getOffsetCdata() + 3)];
				testKey3 = buildPreciseKey(testKey3, testKey3PersistentType, len);
				testKey3Type = buffer[(short) (apdu.getOffsetCdata() + 2)];
			} else if (P2 == (byte) 0x04) {
				if (testKey4 != null) {
					testKey4.clearKey();
				}
				testKey4PersistentType = buffer[(short) (apdu.getOffsetCdata() + 3)];
				testKey4 = buildPreciseKey(testKey4, testKey4PersistentType, len);
				testKey4Type = buffer[(short) (apdu.getOffsetCdata() + 2)];
			} else {
				ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
			}
			break;
		case P1_LOAD_FROM_MAIN:
			// Set from main applet
			if (P2 == (byte) 0x01) {
				if (testKey1 == null) {
					ISOException.throwIt(SW_NOT_SET);
				}
				if (!setKey(testKey1, testKey1Type, testKey1PersistentType, buffer, apdu.getOffsetCdata(), len)) {
					ISOException.throwIt(SW_FAILED_SET);
				}
			} else if (P2 == (byte) 0x02) {
				if (testKey2 == null) {
					ISOException.throwIt(SW_NOT_SET);
				}
				if (!setKey(testKey2, testKey2Type, testKey2PersistentType, buffer, apdu.getOffsetCdata(), len)) {
					ISOException.throwIt(SW_FAILED_SET);
				}
			} else if (P2 == (byte) 0x03) {
				if (testKey3 == null) {
					ISOException.throwIt(SW_NOT_SET);
				}
				if (!setKey(testKey3, testKey3Type, testKey3PersistentType, buffer, apdu.getOffsetCdata(), len)) {
					ISOException.throwIt(SW_FAILED_SET);
				}
			} else if (P2 == (byte) 0x04) {
				if (testKey4 == null) {
					ISOException.throwIt(SW_NOT_SET);
				}
				if (!setKey(testKey4, testKey4Type, testKey4PersistentType, buffer, apdu.getOffsetCdata(), len)) {
					ISOException.throwIt(SW_FAILED_SET);
				}
			} else {
				ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
			}
			break;
		case P1_LOAD_FROM_SUB:
			// Set from alternate static class
			if (P2 == (byte) 0x01) {
				if (testKey1 == null) {
					ISOException.throwIt(SW_NOT_SET);
				}
				AlternateKM.setKey(testKey1, testKey1Type, buffer, apdu.getOffsetCdata(), len);
			} else if (P2 == (byte) 0x02) {
				if (testKey2 == null) {
					ISOException.throwIt(SW_NOT_SET);
				}
				AlternateKM.setKey(testKey2, testKey2Type, buffer, apdu.getOffsetCdata(), len);
			} else if (P2 == (byte) 0x03) {
				if (testKey3 == null) {
					ISOException.throwIt(SW_NOT_SET);
				}
				AlternateKM.setKey(testKey3, testKey3Type, buffer, apdu.getOffsetCdata(), len);
			} else if (P2 == (byte) 0x04) {
				if (testKey4 == null) {
					ISOException.throwIt(SW_NOT_SET);
				}
				AlternateKM.setKey(testKey4, testKey4Type, buffer, apdu.getOffsetCdata(), len);
			} else {
				ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
			}
			break;
		case P1_IS_SET:
			if (P2 == (byte) 0x01) {
				if (!testKey1.isInitialized()) {
					ISOException.throwIt(SW_NOT_SET);
				}
			} else if (P2 == (byte) 0x02) {
				if (!testKey2.isInitialized()) {
					ISOException.throwIt(SW_NOT_SET);
				}
			} else if (P2 == (byte) 0x03) {
				if (!testKey3.isInitialized()) {
					ISOException.throwIt(SW_NOT_SET);
				}
			} else if (P2 == (byte) 0x04) {
				if (!testKey4.isInitialized()) {
					ISOException.throwIt(SW_NOT_SET);
				}
			} else {
				ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
			}
			break;
		case P1_GET:
			if (P2 == (byte) 0x01) {
				len = getKey(testKey1, testKey1PersistentType, buffer, (short) 0);
			} else if (P2 == (byte) 0x02) {
				len = getKey(testKey2, testKey2PersistentType, buffer, (short) 0);
			} else if (P2 == (byte) 0x03) {
				len = getKey(testKey3, testKey3PersistentType, buffer, (short) 0);
			} else if (P2 == (byte) 0x04) {
				len = getKey(testKey4, testKey4PersistentType, buffer, (short) 0);
			} else {
				ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
			}
			apdu.setOutgoingAndSend((short) 0, len);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
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
				if (len <= 0) {
					cipher.init(theKey, Cipher.MODE_ENCRYPT);
				} else {
					cipher.init(theKey, Cipher.MODE_ENCRYPT, buffer, apdu.getOffsetCdata(), len);
				}
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
				if (e.getReason() == CryptoException.ILLEGAL_USE) {
					ISOException.throwIt(Util.makeShort((byte) 0x69, (byte) 0x01));
				} else if (e.getReason() == CryptoException.ILLEGAL_VALUE) {
					ISOException.throwIt(Util.makeShort((byte) 0x69, (byte) 0x02));
				} else if (e.getReason() == CryptoException.INVALID_INIT) {
					ISOException.throwIt(Util.makeShort((byte) 0x69, (byte) 0x03));
				} else if (e.getReason() == CryptoException.NO_SUCH_ALGORITHM) {
					ISOException.throwIt(Util.makeShort((byte) 0x69, (byte) 0x04));
				} else if (e.getReason() == CryptoException.UNINITIALIZED_KEY) {
					ISOException.throwIt(Util.makeShort((byte) 0x69, (byte) 0x05));
				}
			}
			break;
		case P1_FINAL:
			try {
				short ret = cipher.doFinal(buffer, apdu.getOffsetCdata(), len, b0, (short) 0);
				apdu.setOutgoing();
				apdu.setOutgoingLength(ret);
				apdu.sendBytesLong(b0, (short) 0, ret);
			} catch (CryptoException e) {
				if (e.getReason() == CryptoException.ILLEGAL_USE) {
					ISOException.throwIt(Util.makeShort((byte) 0x69, (byte) 0x01));
				} else if (e.getReason() == CryptoException.ILLEGAL_VALUE) {
					ISOException.throwIt(Util.makeShort((byte) 0x69, (byte) 0x02));
				} else if (e.getReason() == CryptoException.INVALID_INIT) {
					ISOException.throwIt(Util.makeShort((byte) 0x69, (byte) 0x03));
				} else if (e.getReason() == CryptoException.NO_SUCH_ALGORITHM) {
					ISOException.throwIt(Util.makeShort((byte) 0x69, (byte) 0x04));
				} else if (e.getReason() == CryptoException.UNINITIALIZED_KEY) {
					ISOException.throwIt(Util.makeShort((byte) 0x69, (byte) 0x05));
				}
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
				if (len <= 0) {
					cipher.init(theKey, Cipher.MODE_DECRYPT);
				} else {
					cipher.init(theKey, Cipher.MODE_DECRYPT, buffer, apdu.getOffsetCdata(), len);
				}
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
				if (signer.verify(arbitraryData, (short) 0, (short) arbitraryData.length, buffer, apdu.getOffsetCdata(),
						len)) {
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

	public void setData(APDU apdu, byte[] buffer) {
		short len = 0;
		byte P1 = buffer[ISO7816.OFFSET_P1];
		byte P2 = buffer[ISO7816.OFFSET_P2];
		switch (P1) {
		case P1_LOAD_FROM_MAIN:
			// Set from main applet
			len = apdu.setIncomingAndReceive();
			if (len <= 0) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
//			arbitraryData = null;
//			arbitraryData = new byte[len];
//			Util.arrayCopy(buffer, apdu.getOffsetCdata(), arbitraryData, (short) 0, len);
			Util.arrayCopyNonAtomic(buffer, apdu.getOffsetCdata(), b1, (short) 0, len);
			break;
		case P1_LOAD_FROM_SUB:
			// Set from alternate class
			len = apdu.setIncomingAndReceive();
			if (len <= 0) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
			arbitraryData = null;
			arbitraryData = new byte[len];
			AlternateKM.setData(buffer, apdu.getOffsetCdata(), arbitraryData, (short) 0, len);
			break;
		case P1_GET:
//			if (len != 4) {
//				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
//			}
//			short getOff = Util.makeShort(buffer[apdu.getOffsetCdata()], buffer[(short) (apdu.getOffsetCdata() + 1)]);
//			short getLen = Util.makeShort(buffer[(short) (apdu.getOffsetCdata() + 2)],
//					buffer[(short) (apdu.getOffsetCdata() + 3)]);
//			Util.arrayCopyNonAtomic(arbitraryData, getOff, buffer, (short) 0, getLen);
//			apdu.setOutgoingAndSend((short) 0, getLen);
			apdu.setOutgoing();
			apdu.setOutgoingLength((short) b1.length); 
			apdu.sendBytesLong(b1, (short) 0, (short) b1.length);
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

	public boolean setKey(Key key, byte keyType, byte testKeyPersistentType, byte[] keyData, short kOff, short kLen) {
		switch (testKeyPersistentType) {
		case KeyBuilder.TYPE_AES:
			((AESKey) key).setKey(keyData, kOff);
			return true;
		case KeyBuilder.TYPE_AES_TRANSIENT_DESELECT:
			((AESKey) key).setKey(keyData, kOff);
			return true;
		case KeyBuilder.TYPE_AES_TRANSIENT_RESET:
			((AESKey) key).setKey(keyData, kOff);
			return true;
		case KeyBuilder.TYPE_DES:
			((DESKey) key).setKey(keyData, kOff);
			return true;
		case KeyBuilder.TYPE_DES_TRANSIENT_DESELECT:
			((DESKey) key).setKey(keyData, kOff);
			return true;
		case KeyBuilder.TYPE_DES_TRANSIENT_RESET:
			((DESKey) key).setKey(keyData, kOff);
			return true;
		case KeyBuilder.TYPE_EC_FP_PRIVATE:
			if (initECCurveParameters((ECKey) key, keyType)) {
				((ECPrivateKey) key).setS(keyData, kOff, kLen);
				return true;
			}
			break;
		case KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT:
			if (initECCurveParameters((ECKey) key, keyType)) {
				((ECPrivateKey) key).setS(keyData, kOff, kLen);
				return true;
			}
			break;
		case KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_RESET:
			if (initECCurveParameters((ECKey) key, keyType)) {
				((ECPrivateKey) key).setS(keyData, kOff, kLen);
				return true;
			}
			break;
		case KeyBuilder.TYPE_EC_FP_PUBLIC:
			if (initECCurveParameters((ECKey) key, keyType)) {
				((ECPublicKey) key).setW(keyData, kOff, kLen);
				return true;
			}
			break;
		default:
			break;
		}
		return false;
	}

	public boolean initECCurveParameters(ECKey key, byte keyType) {
		if (keyType == KEY_EC_SECP_256_R1) {
			key.setA(Constants.ansix9p256r1_a, (short) 0, (short) Constants.ansix9p256r1_a.length);
			key.setB(Constants.ansix9p256r1_b, (short) 0, (short) Constants.ansix9p256r1_b.length);
			key.setG(Constants.ansix9p256r1_g, (short) 0, (short) Constants.ansix9p256r1_g.length);
			key.setR(Constants.ansix9p256r1_r, (short) 0, (short) Constants.ansix9p256r1_r.length);
			key.setFieldFP(Constants.ansix9p256r1_field, (short) 0, (short) Constants.ansix9p256r1_field.length);
			key.setK((short) 1);
			return true;
		} else if (keyType == KEY_EC_SECP_384_R1) {
			key.setA(Constants.ansix9p384r1_a, (short) 0, (short) Constants.ansix9p384r1_a.length);
			key.setB(Constants.ansix9p384r1_b, (short) 0, (short) Constants.ansix9p384r1_b.length);
			key.setG(Constants.ansix9p384r1_g, (short) 0, (short) Constants.ansix9p384r1_g.length);
			key.setR(Constants.ansix9p384r1_r, (short) 0, (short) Constants.ansix9p384r1_r.length);
			key.setFieldFP(Constants.ansix9p384r1_field, (short) 0, (short) Constants.ansix9p384r1_field.length);
			key.setK((short) 1);
			return true;
		} else if (keyType == KEY_EC_SECP_521_R1) {
			key.setA(Constants.ansix9p521r1_a, (short) 0, (short) Constants.ansix9p521r1_a.length);
			key.setB(Constants.ansix9p521r1_b, (short) 0, (short) Constants.ansix9p521r1_b.length);
			key.setG(Constants.ansix9p521r1_g, (short) 0, (short) Constants.ansix9p521r1_g.length);
			key.setR(Constants.ansix9p521r1_r, (short) 0, (short) Constants.ansix9p521r1_r.length);
			key.setFieldFP(Constants.ansix9p521r1_field, (short) 0, (short) Constants.ansix9p521r1_field.length);
			key.setK((short) 1);
			return true;
		} else if (keyType == KEY_EC_SECP_256_K1) {
			key.setA(Constants.SECP256K1_A, (short) 0, (short) Constants.SECP256K1_A.length);
			key.setB(Constants.SECP256K1_B, (short) 0, (short) Constants.SECP256K1_B.length);
			key.setG(Constants.SECP256K1_G, (short) 0, (short) Constants.SECP256K1_G.length);
			key.setR(Constants.SECP256K1_R, (short) 0, (short) Constants.SECP256K1_R.length);
			key.setFieldFP(Constants.SECP256K1_FIELD, (short) 0, (short) Constants.SECP256K1_FIELD.length);
			key.setK((short) 1);
			return true;
		} else if (keyType == KEY_EC_BRAINPOOL_256_R1) {
			key.setA(Constants.brainpoolP256r1_a, (short) 0, (short) Constants.brainpoolP256r1_a.length);
			key.setB(Constants.brainpoolP256r1_b, (short) 0, (short) Constants.brainpoolP256r1_b.length);
			key.setG(Constants.brainpoolP256r1_g, (short) 0, (short) Constants.brainpoolP256r1_g.length);
			key.setR(Constants.brainpoolP256r1_r, (short) 0, (short) Constants.brainpoolP256r1_r.length);
			key.setFieldFP(Constants.brainpoolP256r1_field, (short) 0, (short) Constants.brainpoolP256r1_field.length);
			key.setK((short) 1);
			return true;
		} else if (keyType == KEY_EC_BRAINPOOL_384_R1) {
			key.setA(Constants.brainpoolP384r1_a, (short) 0, (short) Constants.brainpoolP384r1_a.length);
			key.setB(Constants.brainpoolP384r1_b, (short) 0, (short) Constants.brainpoolP384r1_b.length);
			key.setG(Constants.brainpoolP384r1_g, (short) 0, (short) Constants.brainpoolP384r1_g.length);
			key.setR(Constants.brainpoolP384r1_r, (short) 0, (short) Constants.brainpoolP384r1_r.length);
			key.setFieldFP(Constants.brainpoolP384r1_field, (short) 0, (short) Constants.brainpoolP384r1_field.length);
			key.setK((short) 1);
			return true;
		} else if (keyType == KEY_EC_BRAINPOOL_512_R1) {
			try {
				((ECKey) key).setA(Constants.brainpoolP512r1_a, (short) 0, (short) Constants.brainpoolP512r1_a.length);
			} catch (Exception e) {
				ISOException.throwIt(Util.makeShort((byte) 0x6f, (byte) 0xb1));
			}
			try {
				((ECKey) key).setB(Constants.brainpoolP512r1_b, (short) 0, (short) Constants.brainpoolP512r1_b.length);
			} catch (Exception e) {
				ISOException.throwIt(Util.makeShort((byte) 0x6f, (byte) 0xb2));
			}
			try {
				((ECKey) key).setG(Constants.brainpoolP512r1_g, (short) 0, (short) Constants.brainpoolP512r1_g.length);
			} catch (Exception e) {
				ISOException.throwIt(Util.makeShort((byte) 0x6f, (byte) 0xb3));
			}
			try {
				((ECKey) key).setR(Constants.brainpoolP512r1_r, (short) 0, (short) Constants.brainpoolP512r1_r.length);
			} catch (Exception e) {
				ISOException.throwIt(Util.makeShort((byte) 0x6f, (byte) 0xb4));
			}
			try {
				((ECKey) key).setFieldFP(Constants.brainpoolP512r1_field, (short) 0,
						(short) Constants.brainpoolP512r1_field.length);
			} catch (Exception e) {
				ISOException.throwIt(Util.makeShort((byte) 0x6f, (byte) 0xb5));
			}
			try {
				((ECKey) key).setK((short) 1);
			} catch (Exception e) {
				ISOException.throwIt(Util.makeShort((byte) 0x6f, (byte) 0xb6));
			}
			return true;
		} else {
			return false;
		}
	}
}
