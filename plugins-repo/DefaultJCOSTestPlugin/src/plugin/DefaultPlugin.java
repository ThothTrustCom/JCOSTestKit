package plugin;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.HashMap;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import interfaces.BinUtils;
import interfaces.DeviceHelper;
import interfaces.TestDevice;
import interfaces.TestFunctionInterface;

public class DefaultPlugin implements TestFunctionInterface {

	public static final String pluginName = "Default Test Plugin";
	public static final String shortDescription = "Default test plugin for JCOS test kit.";
	public static final byte ALG_MD5 = (byte) 0x02;
	public static final byte ALG_NULL = (byte) 0x00;
	public static final byte ALG_RIPEMD160 = (byte) 0x03;
	public static final byte ALG_SHA = (byte) 0x01;
	public static final byte ALG_SHA_224 = (byte) 0x07;
	public static final byte ALG_SHA_256 = (byte) 0x04;
	public static final byte ALG_SHA_384 = (byte) 0x05;
	public static final byte ALG_SHA_512 = (byte) 0x06;
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
	public static String[] hashAlgoJCE = { "MD5", "RIPEMD160", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512" };
	public static byte[] hashAlgoJC = { ALG_MD5, ALG_RIPEMD160, ALG_SHA, ALG_SHA_224, ALG_SHA_256, ALG_SHA_384,
			ALG_SHA_512 };
	public static String[] ecAlgoTest = { "SECP-256R1", "SECP-384R1", "SECP-521R1", "SECP-256K1", "BrainPool-256R1",
			"BrainPool-384R1", "BrainPool-512R1" };
	public static byte[] ecAlgo = { KEY_EC_SECP_256_R1, KEY_EC_SECP_384_R1, KEY_EC_SECP_521_R1, KEY_EC_SECP_256_K1,
			KEY_EC_BRAINPOOL_256_R1, KEY_EC_BRAINPOOL_384_R1, KEY_EC_BRAINPOOL_512_R1 };
	public static short[] ecPrivateKeyLen = { 32, 48, 64, 32, 32, 48, 64 };
	public static short[] ecPrivateKeyBitLength = { 256, 384, 521, 256, 256, 384, 521 };
	public static SecureRandom rand = new SecureRandom();

	@Override
	public HashMap<String, Object> process(TestDevice device) {
		try {
			System.out.println("Device's ATR: " + BinUtils.toHexString(device.getATRBytes()));

			System.out.println("Begin overload test ...");

			// Arbitrary data upload and download test
			System.out.println(
					"Begin arbitrary upload of \"canary\" message to detect memory corruption after tests ...");
			byte[] message1 = new byte[255];
			rand.nextBytes(message1);
			System.out.println("Message Length: " + message1.length + " bytes");
			System.out.println("Data to upload: \r\n" + BinUtils.toHexString(message1));

			uploadArbitraryDataChunk(device, message1);

			System.out.println("\r\n########## Begin Hash testing ##########");
			
			int messageLen = 100000;
			byte[] message = new byte[messageLen];

			rand.nextBytes(message);			

			for (int h = 0; h < hashAlgoJCE.length; h++) {
				System.out.println("Testing with hash: " + hashAlgoJCE[h]);

				// Set hash algorithm
				if (readyHash(device, hashAlgoJC[h])) {

					// Reset hash internal state
					resetHash(device);

					// Do hashing
					int hashedLen = 0;
					byte[] tempBuffer = null;
					byte[] finalDeviceResult = null;
					while (hashedLen < messageLen) {
						if ((messageLen - hashedLen) > 255) {
							// Buffer 255 random bytes and update hash
							tempBuffer = new byte[255];
							System.arraycopy(message, hashedLen, tempBuffer, 0, 255);
							updateHashData(device, tempBuffer);
						} else {
							// Buffer remaining random bytes and finalize hash
							tempBuffer = new byte[(messageLen - hashedLen)];
							System.arraycopy(message, hashedLen, tempBuffer, 0, tempBuffer.length);
							finalDeviceResult = doFinalHashData(device, tempBuffer);
						}

						// Increment tempBuffer
						hashedLen += tempBuffer.length;
					}

					// Use JCE Hashing to produce hash of the message for independent checking
					MessageDigest md = MessageDigest.getInstance(hashAlgoJCE[h]);
					md.update(message);
					byte[] finalJCEResult = md.digest();

					// Display results
					System.out.println("Card Result: " + BinUtils.toHexString(finalDeviceResult));
					System.out.println("JCE  Result: " + BinUtils.toHexString(finalJCEResult));

					// Compare JCE and Card results
					if (BinUtils.binArrayElementsCompare(finalDeviceResult, 0, finalJCEResult, 0,
							finalDeviceResult.length) && (finalDeviceResult.length == finalJCEResult.length)) {
						System.out.println("Hashing on device is CORRECT");
					} else {
						System.out.println("Hashing on device is WRONG");
					}
				} else {
					System.out.println("Hash: " + hashAlgoJCE[h] + " is not available ...");
				}
			}

			System.out.println("\r\n########## Begin JCVM Java testing ##########");

			JCVMInstanceOfTest(device);

			System.out.println("\r\n########## Begin key setting test from Main Applet ##########");

			for (int h = 0; h < ecAlgoTest.length; h++) {
				System.out.println("Testing with key type: " + ecAlgoTest[h]);

				boolean setFromMainApplet = true;
				byte keyID = (byte) 0x01;
				byte ecKeyPrivatePersistentType = (byte) 0x0C; // TYPE_EC_FP_PRIVATE - 12
				byte[] privateBytes = new byte[ecPrivateKeyLen[h]]; // get key length
				rand.nextBytes(privateBytes);
				System.out
						.println("Setting Private Key for [" + ecAlgoTest[h] + "]: " + setKey(device, keyID, ecAlgo[h],
								ecKeyPrivatePersistentType, privateBytes, ecPrivateKeyBitLength[h], setFromMainApplet));
			}

			System.out.println("\r\n########## Begin key setting test from Sub Applet ##########");

			for (int h = 0; h < ecAlgoTest.length; h++) {
				System.out.println("Testing with key type: " + ecAlgoTest[h]);

				boolean setFromMainApplet = false;
				byte keyID = (byte) 0x01;
				byte ecKeyPrivatePersistentType = (byte) 0x0C; // TYPE_EC_FP_PRIVATE - 12
				byte[] privateBytes = new byte[ecPrivateKeyLen[h]]; // get key length
				rand.nextBytes(privateBytes);
				System.out
						.println("Setting Private Key for [" + ecAlgoTest[h] + "]: " + setKey(device, keyID, ecAlgo[h],
								ecKeyPrivatePersistentType, privateBytes, ecPrivateKeyBitLength[h], setFromMainApplet));
			}

			System.out.println("\r\n########## Testing DES Crypto ##########");
			DESCryptoTest(device);
			
			System.out.println("\r\n########## Testing AES Crypto ##########");
			AESCryptoTest(device);

			System.out.println("\r\n########## Testing ECC Crypto ##########");
			ECCryptoTest(device);

			System.out.println("\r\n######## Comparing Canary Data ########");
			byte[] downloadData = downloadArbitraryDataChunk(device);
			System.out.println("Data download: \r\n" + BinUtils.toHexString(downloadData));
			System.out.println("Data are same ? "
					+ BinUtils.binArrayElementsCompare(message1, 0, downloadData, 0, message1.length));
		} catch (CardException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException
				| InvalidParameterSpecException | SignatureException e) {
			System.out.println(">>> Exception found ...");
			e.printStackTrace();
		}
		return null;
	}

	public static boolean JCVMInstanceOfTest(TestDevice tempDev) throws CardException {
		System.out.println("Begin Java instanceof type matching test ...");
		// Creating AES key and using JC's instanceof to check if JCVM correctly
		// identifies AESKey type (0x02) as result
		ResponseAPDU resp = tempDev.send(new CommandAPDU((byte) 0xB0, INS_JAVA, (byte) 0x01, (byte) 0x00, 255));
		if (DeviceHelper.isSuccessfulResponse(resp)) {
			byte[] respSuccessData = DeviceHelper.getSuccessfulResponseData(resp);
			if (respSuccessData.length == 1) {
				if (respSuccessData[0] == (byte) 0x02) {
					System.out.println("JCVM's instanceof test is OK ...");
					return true;
				}
			}
		}
		System.out.println("[ERR] JCVM's instanceof FAILED !!!");
		System.out.println(BinUtils.toHexString(resp.getBytes()));
		return false;
	}

	public static boolean readyHash(TestDevice tempDev, byte hashAlgo) throws CardException {
		ResponseAPDU resp = tempDev.send(new CommandAPDU((byte) 0xB0, INS_HASH, P1_SET, hashAlgo));
//		System.out.println("Ready Hash Response: " + BinUtils.toHexString(resp.getBytes()));
		if (DeviceHelper.isSuccessfulResponse(resp)) {
			System.out.println("Hash is READY ...");
			return true;
		} else {
			System.out.println("[ERR] Hash is NOT READY !!!");
			System.out.println(BinUtils.toHexString(resp.getBytes()));
			return false;
		}
	}

	public static void resetHash(TestDevice tempDev) throws CardException {
		ResponseAPDU resp = tempDev.send(new CommandAPDU((byte) 0xB0, INS_HASH, P1_RESET, (byte) 0x00));
//		System.out.println("Reset Hash Response: " + BinUtils.toHexString(resp.getBytes()));
		if (!DeviceHelper.isSuccessfulResponse(resp)) {
			System.out.println("[ERR] Hash reset failed !!!");
			System.out.println(BinUtils.toHexString(resp.getBytes()));
		}
	}

	public static void updateHashData(TestDevice tempDev, byte[] data) throws CardException {
		ResponseAPDU resp = tempDev.send(new CommandAPDU((byte) 0xB0, INS_HASH, P1_UPDATE, (byte) 0x00, data));
//		System.out.println("Update Hash Response: " + BinUtils.toHexString(resp.getBytes()));
		if (!DeviceHelper.isSuccessfulResponse(resp)) {
			System.out.println("[ERR] Hash update failed !!!");
			System.out.println(BinUtils.toHexString(resp.getBytes()));
		}
	}

	public static byte[] doFinalHashData(TestDevice tempDev, byte[] data) throws CardException {
		ResponseAPDU resp = tempDev.send(new CommandAPDU((byte) 0xB0, INS_HASH, P1_FINAL, (byte) 0x00, data, 255));
//		System.out.println("Finalized Hash Response: " + BinUtils.toHexString(resp.getBytes()));
		if (DeviceHelper.isSuccessfulResponse(resp)) {
			return DeviceHelper.getSuccessfulResponseData(resp);
		} else {
			System.out.println("[ERR] Hash finalization failed !!!");
			System.out.println(BinUtils.toHexString(resp.getBytes()));
		}
		return null;
	}

	public static boolean readyCrypto(TestDevice tempDev, byte cryptoMode, byte algoMode) throws CardException {
		ResponseAPDU resp = tempDev.send(new CommandAPDU((byte) 0xB0, cryptoMode, P1_SET, algoMode));
		System.out.println("Algo Mode: " + BinUtils.toHexString(new byte[] { algoMode }));
		if (DeviceHelper.isSuccessfulResponse(resp)) {
			System.out.println("Crypto is READY ...");
			return true;
		} else {
			System.out.println("[ERR] Crypto is NOT READY !!!");
			System.out.println(BinUtils.toHexString(resp.getBytes()));
			return false;
		}
	}

	public static void resetCrypto(TestDevice tempDev, byte cryptoMode, byte keyID, byte[] parameter)
			throws CardException {
		CommandAPDU cmd;
//		System.out.println("CRYPTRESET :: INS = " + BinUtils.toHexString(new byte[] {cryptoMode}) + ", P2 = " + BinUtils.toHexString(new byte[] {keyID}));
		if (parameter != null) {
			cmd = new CommandAPDU((byte) 0xB0, cryptoMode, P1_RESET, keyID, parameter);
//			System.out.println("Parameter = " + BinUtils.toHexString(parameter));
		} else {
			cmd = new CommandAPDU((byte) 0xB0, cryptoMode, P1_RESET, keyID);
		}

		ResponseAPDU resp = tempDev.send(cmd);
//		System.out.println("Reset Hash Response: " + BinUtils.toHexString(resp.getBytes()));
		if (!DeviceHelper.isSuccessfulResponse(resp)) {
			System.out.println("[ERR] Crypto reset failed !!!");
			System.out.println(BinUtils.toHexString(resp.getBytes()));
		}
	}

	public static byte[] updateCryptoData(TestDevice tempDev, byte cryptoMode, byte[] data) {
//		System.out.println("CRYPTUPDATE :: INS = " + BinUtils.toHexString(new byte[] {cryptoMode}) + ", Data = \r\n" + BinUtils.toHexString(data));
		ResponseAPDU resp = null;
		try {
			resp = tempDev.send(new CommandAPDU((byte) 0xB0, cryptoMode, P1_UPDATE, (byte) 0x00, data, 255));
		} catch (CardException e) {
			e.printStackTrace();
		}
		if (DeviceHelper.isSuccessfulResponse(resp)) {
			return DeviceHelper.getSuccessfulResponseData(resp);
		} else {
			System.out.println("[ERR] Crypto update failed !!!");
			System.out.println(BinUtils.toHexString(resp.getBytes()));
		}
		return null;
	}

	public static byte[] doFinalCryptoData(TestDevice tempDev, byte cryptoMode, byte[] data) throws CardException {
		ResponseAPDU resp = tempDev.send(new CommandAPDU((byte) 0xB0, cryptoMode, P1_FINAL, (byte) 0x00, data, 255));
		if (DeviceHelper.isSuccessfulResponse(resp)) {
			return DeviceHelper.getSuccessfulResponseData(resp);
		} else {
			System.out.println("[ERR] Crypto finalization failed !!!");
			System.out.println(BinUtils.toHexString(resp.getBytes()));
		}
		return null;
	}

	public static boolean DESCryptoTest(TestDevice tempDev)
			throws CardException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		// Overload data test
		byte[] cardCryptoModes = { INS_ENCRYPT, INS_DECRYPT };
		byte[] desCardCipherModes = { (byte) 0x05 /* , (byte) 0x08, (byte) 0x01, (byte) 0x04 */ };
		int[] desKeyLength = { 8 /* , 16, 24 */ };
		int[] jceCryptoModes = { Cipher.ENCRYPT_MODE, Cipher.DECRYPT_MODE };
		String[] cryptoModesNames = { "Encrypt Mode", "Decrypt Mode" }; //
		String[] desCardCipherModesNames = {
				"ALG_DES_ECB_NOPAD" /*
									 * , "ALG_DES_ECB_PKCS5", "ALG_DES_CBC_NOPAD", "ALG_DES_CBC_PKCS5"
									 */ };
		String[] tripleDESSJCECipherModes = {
				"DESede/ECB/NoPadding" /*
										 * , "DESede/ECB/PKCS5Padding", "DESede/CBC/NoPadding",
										 * "DESede/CBC/PKCS5Padding"
										 */ };
		String[] desJCECipherModes = {
				"DES/ECB/NoPadding" /*
									 * , "DES/ECB/PKCS5Padding", "DES/CBC/NoPadding", "DES/CBC/PKCS5Padding"
									 */ };
		String[] desKeyLengthNames = { "Single DES Key" /* , "Double DES Key", "Tripe DES Key" */ };

		// Set key ID '1' with DES key
		boolean setFromMainApplet = true;
		byte keyID = (byte) 0x01;
		byte keyPersistentType = (byte) 0x01; // TYPE_DES - 3, TYPE_DES_TRANSIENT_RESET - 1
		boolean allowProceed = true;
		Cipher jceDesCipher = null;
		int testDataSize = 100000;
		int dataSize = testDataSize;
		byte[] parameter = null;
		byte[] data = null;
		byte[] data1 = null;
		byte[] outputCard = null;
		byte[] outputJCE = null;
		int outputCardCount = 0;
		int recvCardCount = 0;

		for (int i = 0; i < desKeyLength.length; i++) {
			byte[] secretBytes = new byte[desKeyLength[i]]; // get key length
			rand.nextBytes(secretBytes);

			// Set key for JCE side
			SecretKeySpec desKeySpec = null;

			if (i == 0) {
				desKeySpec = new SecretKeySpec(secretBytes, "DES");
			} else {
				desKeySpec = new SecretKeySpec(secretBytes, "DESede");
			}

			// Set key for Card side
			allowProceed = setKey(tempDev, keyID, (byte) 0x00, keyPersistentType, secretBytes,
					(short) (desKeyLength[i] * 8), setFromMainApplet);
			System.out.println("Setting Key for [" + desKeyLengthNames[i] + "]: " + allowProceed);

			if (allowProceed) {
				// Successfully set DES key

				// Iterate through DES ciphering modes to test them
				for (int j = 0; j < desCardCipherModes.length; j++) {

					// Generate IV params according to cipher mode
					if (j > 1) {
						parameter = new byte[8]; // CBC modes with IV all zeros
					} else {
						parameter = null; // ECB modes no IV
					}

					// Iterate through Cipher.MODE types
					for (int k = 0; k < cardCryptoModes.length; k++) {

						// Setup card Cipher instance
						System.out.println("Begin setting crypto mode [" + cryptoModesNames[k] + "] for cipher mode ["
								+ desCardCipherModesNames[j] + "] on card...");
						boolean isCardReady = readyCrypto(tempDev, cardCryptoModes[k], desCardCipherModes[j]);

						// Setup JCE Cipher instance according to key length
						if (i == 0) {
							System.out.println("Begin setting crypto mode [" + desJCECipherModes[j] + "] for JCE ...");
							// Single DES operation, use desJCECipherModes
							jceDesCipher = Cipher.getInstance(desJCECipherModes[j]);
						} else {
							// TripleDES operation, use tripleDESSJCECipherModes
							jceDesCipher = Cipher.getInstance(tripleDESSJCECipherModes[j]);
							System.out.println(
									"Begin setting crypto mode [" + tripleDESSJCECipherModes[j] + "] for JCE ...");
						}

						if (isCardReady && jceDesCipher != null) {
							// Execute cipher on card

							// Setup test data
							if (data == null) {
								// Generate new data
								data = new byte[dataSize];
								rand.nextBytes(data);
							}

//							System.out.println("Data: \r\n" + BinUtils.toHexString(data));

							// Initialize cipher with IV parameter according to cipher modes on card
							resetCrypto(tempDev, cardCryptoModes[k], keyID, parameter);

							// Create output buffers
							outputCard = new byte[dataSize + 16];
							outputJCE = null;
							outputCardCount = 0;
							recvCardCount = 0;

							System.out.println("Uploading data ...");

							// Update data chunks
							byte[] tempOutBuffer = null;
							byte[] tempInBuffer = null;
							while (outputCardCount < dataSize) {
								if ((dataSize - outputCardCount) > 248) {
									// Buffer 248 bytes and update
									tempOutBuffer = new byte[248];
									System.arraycopy(data, outputCardCount, tempOutBuffer, 0, 248);
//									System.out.println("Sending: " + BinUtils.toHexString(tempOutBuffer));
									tempInBuffer = updateCryptoData(tempDev, cardCryptoModes[k], tempOutBuffer);
//									if (tempInBuffer != null) {
//										System.out.println("Recving: " + BinUtils.toHexString(tempInBuffer));
//									}
								} else {
									// Buffer remaining bytes and finalize
									tempOutBuffer = new byte[(dataSize - outputCardCount)];
									System.arraycopy(data, outputCardCount, tempOutBuffer, 0, tempOutBuffer.length);
//									System.out.println("Sending: " + BinUtils.toHexString(tempOutBuffer));
									tempInBuffer = doFinalCryptoData(tempDev, cardCryptoModes[k], tempOutBuffer);
//									if (tempInBuffer != null) {
//										System.out.println("Recving: " + BinUtils.toHexString(tempInBuffer));
//									}
								}

								if (tempInBuffer == null) {
									allowProceed = false;
									data = null;
									data1 = null;
									outputCardCount = 0;
									break;
								}

								// Copy current result to main result buffer
								System.arraycopy(tempInBuffer, 0, outputCard, outputCardCount, tempInBuffer.length);

								// Increment tempBuffer
								outputCardCount += tempOutBuffer.length;
								recvCardCount += tempInBuffer.length;
							}

							if (allowProceed) {
								System.out.println("Finish uploading data ...");
//								System.out.println("Processed on Card: " + outputCardCount);
//								System.out.println("Card Result: \r\n" + BinUtils.toHexString(outputCard));

								// Execute cipher on JCE
								// Initialize cipher with IV parameter according to cipher modes on JCE
								if (parameter != null) {
									System.out.println("IV: " + BinUtils.toHexString(parameter));

									IvParameterSpec iv = new IvParameterSpec(parameter);
									jceDesCipher.init(jceCryptoModes[k], desKeySpec, iv);
								} else {
									jceDesCipher.init(jceCryptoModes[k], desKeySpec);
								}

								// Cipher operation

								outputJCE = jceDesCipher.doFinal(data);
//								System.out.println("Processed on JCE: " + outputJCE.length);
//								System.out.println("JCE Result: \r\n" + BinUtils.toHexString(outputJCE));

								// If encrypt mode, retain output and reuse in subsequent decrypt mode
								if (k == 0) {
									data1 = data;
									data = outputJCE;
									dataSize = outputJCE.length;
								}

								// If decrypt mode, set data back to null to allow regeneration
								if (k == 1) {
									data = null;
									dataSize = testDataSize;
								}

								// Comparison of outputs
								if (recvCardCount == outputJCE.length && BinUtils.binArrayElementsCompare(outputCard, 0,
										outputJCE, 0, outputJCE.length)) {
									System.out.println("[INF] Cipher results MATCH !!!");
								} else {
									System.out.println("[ERR] Cipher results NOT MATCH !!!");
								}

								data1 = null;
							} else {
								System.out.println("[ERR] Skipping comparison due to FATAL cipher operation error !!!");
								allowProceed = true;
							}
						} else {
							// Failed to initialize cipher
							System.out.println("[ERR] Cipher initialization failed !!!");
						}
					}
				}
			}

			System.out.println("\r\nGetting key material ...");
			System.out.println("Key Material: " + BinUtils.toHexString(getKey(tempDev, (byte) 0x01)));
		}

		return false;
	}

	public static boolean AESCryptoTest(TestDevice tempDev)
			throws CardException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		// Overload data test
		byte[] cardCryptoModes = { INS_ENCRYPT, INS_DECRYPT };
		byte[] aesCardCipherModes = { (byte) 0x0E, (byte) 0x1B, (byte) 0x0D, (byte) 0x18 };
		int[] aesKeyLength = { 16, 24, 32 };
		int[] jceCryptoModes = { Cipher.ENCRYPT_MODE, Cipher.DECRYPT_MODE };
		String[] cryptoModesNames = { "Encrypt Mode", "Decrypt Mode" };
		String[] aesCardCipherModesNames = { "ALG_AES_BLOCK_128_ECB_NOPAD", "ALG_AES_ECB_PKCS5",
				"ALG_AES_BLOCK_128_CBC_NOPAD", "ALG_AES_CBC_PKCS5" };
		String[] aesJCECipherModes = { "AES/ECB/NoPadding", "AES/ECB/PKCS5Padding", "AES/CBC/NoPadding",
				"AES/CBC/PKCS5Padding" };
		String[] aesKeyLengthNames = { "128-bit AES Key", "192-bit AES Key", "256-bit AES Key" };

		// Set key ID '1' with AES key
		boolean setFromMainApplet = true;
		byte keyID = (byte) 0x01;
		byte keyPersistentType = (byte) 0x0F; // TYPE_AES - 15, TYPE_AES_TRANSIENT_RESET - 13
		boolean allowProceed = true;
		Cipher jceAesCipher = null;
		int testDataSize = 100000;
		int dataSize = testDataSize;
		byte[] parameter = null;
		byte[] data = null;
		byte[] data1 = null;
		byte[] outputCard = null;
		byte[] outputJCE = null;
		int outputCardCount = 0;
		int recvCardCount = 0;

		for (int i = 0; i < aesKeyLength.length; i++) {
			byte[] secretBytes = new byte[aesKeyLength[i]]; // get key length
			rand.nextBytes(secretBytes);

			// Set key for JCE side
			SecretKeySpec aesKeySpec = null;

			aesKeySpec = new SecretKeySpec(secretBytes, "AES");

			// Set key for Card side
			allowProceed = setKey(tempDev, keyID, (byte) 0x00, keyPersistentType, secretBytes,
					(short) (aesKeyLength[i] * 8), setFromMainApplet);
			System.out.println("Setting Key for [" + aesKeyLengthNames[i] + "]: " + allowProceed);

			if (allowProceed) {
				// Successfully set AES key

				// Iterate through AES ciphering modes to test them
				for (int j = 0; j < aesCardCipherModes.length; j++) {

					// Generate IV params according to cipher mode
					if (j > 1) {
						parameter = new byte[16]; // CBC modes with IV all zeros
					} else {
						parameter = null; // ECB modes no IV
					}

					// Iterate through Cipher.MODE types
					for (int k = 0; k < cardCryptoModes.length; k++) {

						// Setup card Cipher instance
						System.out.println("Begin setting crypto mode [" + cryptoModesNames[k] + "] for cipher mode ["
								+ aesCardCipherModesNames[j] + "] on card...");
						boolean isCardReady = readyCrypto(tempDev, cardCryptoModes[k], aesCardCipherModes[j]);

						// Setup JCE Cipher instance
						System.out.println("Begin setting crypto mode [" + aesJCECipherModes[j] + "] for JCE ...");
						jceAesCipher = Cipher.getInstance(aesJCECipherModes[j]);

						if (isCardReady && jceAesCipher != null) {
							// Execute cipher on card

							// Setup test data
							if (data == null) {
								// Generate new data
								data = new byte[dataSize];
								rand.nextBytes(data);
							}

//							System.out.println("Data: \r\n" + BinUtils.toHexString(data));

							// Initialize cipher with IV parameter according to cipher modes on card
							resetCrypto(tempDev, cardCryptoModes[k], keyID, parameter);

							// Create output buffers
							outputCard = new byte[dataSize + 32];
							outputJCE = null;
							outputCardCount = 0;
							recvCardCount = 0;

							System.out.println("Uploading data ...");

							// Update data chunks
							byte[] tempOutBuffer = null;
							byte[] tempInBuffer = null;
							while (outputCardCount < dataSize) {
//								System.out.println("OC: " + outputCardCount + ", IS: " + dataSize);

								if ((dataSize - outputCardCount) > 248) {
									// Buffer 248 bytes and update
									tempOutBuffer = new byte[248];
									System.arraycopy(data, outputCardCount, tempOutBuffer, 0, 248);
//									System.out.println("Sending: " + BinUtils.toHexString(tempOutBuffer));
									tempInBuffer = updateCryptoData(tempDev, cardCryptoModes[k], tempOutBuffer);
//									if (tempInBuffer != null) {
//										System.out.println("Recving: " + BinUtils.toHexString(tempInBuffer));
//									}
								} else {
									// Buffer remaining bytes and finalize
									tempOutBuffer = new byte[(dataSize - outputCardCount)];
									System.arraycopy(data, outputCardCount, tempOutBuffer, 0, tempOutBuffer.length);
//									System.out.println("Sending: " + BinUtils.toHexString(tempOutBuffer));
									tempInBuffer = doFinalCryptoData(tempDev, cardCryptoModes[k], tempOutBuffer);
//									if (tempInBuffer != null) {
//										System.out.println("Recving: " + BinUtils.toHexString(tempInBuffer));
//									}
								}

								if (tempInBuffer == null) {
									allowProceed = false;
									data = null;
									data1 = null;
									outputCardCount = 0;
									break;
								}

								// Copy current result to main result buffer
//								System.out.println("OC: " + outputCardCount + ", IS: " + dataSize + ", TI: " + tempInBuffer.length);
								System.arraycopy(tempInBuffer, 0, outputCard, recvCardCount, tempInBuffer.length);

								// Increment tempBuffer
								outputCardCount += tempOutBuffer.length;
								recvCardCount += tempInBuffer.length;
							}

							if (allowProceed) {
								System.out.println("Finish uploading data ...");
//								System.out.println("Card Result: \r\n" + BinUtils.toHexString(outputCard));

								// Execute cipher on JCE
								// Initialize cipher with IV parameter according to cipher modes on JCE
								if (parameter != null) {
									System.out.println("IV: " + BinUtils.toHexString(parameter));
									IvParameterSpec iv = new IvParameterSpec(parameter);
									jceAesCipher.init(jceCryptoModes[k], aesKeySpec, iv);
								} else {
									jceAesCipher.init(jceCryptoModes[k], aesKeySpec);
								}

								// Cipher operation

								outputJCE = jceAesCipher.doFinal(data);
//								System.out.println("JCE Result: \r\n" + BinUtils.toHexString(outputJCE));

								// If encrypt mode, retain output and reuse in subsequent decrypt mode
								if (k == 0) {
									data1 = data;
									data = outputJCE;
									dataSize = outputJCE.length;
								}

								// If decrypt mode, set data back to null to allow regeneration
								if (k == 1) {
									data = null;
									dataSize = testDataSize;
								}

								// Comparison of outputs
//								System.out.println("Card result bytes: " + recvCardCount);
//								System.out.println("JCE result bytes: " + recvCardCount);
								if (recvCardCount == outputJCE.length && BinUtils.binArrayElementsCompare(outputCard, 0,
										outputJCE, 0, outputJCE.length)) {
									System.out.println("[INF] Cipher results MATCH !!!");
								} else {
									System.out.println("[ERR] Cipher results NOT MATCH !!!");
								}

								data1 = null;
							} else {
								System.out.println("[ERR] Skipping comparison due to FATAL cipher operation error !!!");
								allowProceed = true;
							}
						} else {
							// Failed to initialize cipher
							System.out.println("[ERR] Cipher initialization failed !!!");
						}
					}
				}
			}

			System.out.println("\r\nGetting key material ...");
			System.out.println("Key Material: " + BinUtils.toHexString(getKey(tempDev, (byte) 0x01)));
		}

		return false;
	}

	public static boolean ECCryptoTest(TestDevice tempDev) throws CardException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException, InvalidParameterSpecException, SignatureException {
		// Overload data test
		byte[] cardCryptoModes = { INS_SIGN, INS_DERIVE };
		byte[] ecdsaCardCipherModes = { (byte) 0x11, (byte) 0x25, (byte) 0x21, (byte) 0x22, (byte) 0x26 };
		byte[] ecdhCardCipherModes = { (byte) 0x01, (byte) 0x03 }; // ALG_EC_SVDP_DH = 1, ALG_EC_SVDP_DH_PLAIN = 3
		int[] eccKeyLength = { 32, 48 };
		byte[] eccKeyType = { KEY_EC_SECP_256_R1, KEY_EC_SECP_384_R1 };
		String[] eccJCEKeyLengthName = { "secp256r1", "secp384r1" };
		String[] cryptoModesNames = { "Sign Mode", "Derive Mode" };
		String[] ecdsaCardCipherModesNames = { "ALG_ECDSA_SHA", "ALG_ECDSA_SHA_224", "ALG_ECDSA_SHA_256",
				"ALG_ECDSA_SHA_384", "ALG_ECDSA_SHA_512" };
		String[] ecdhCardCipherModesNames = { "ALG_EC_SVDP_DH", "ALG_EC_SVDP_DH_PLAIN" };
		String[] ecdsaJCECipherModes = { "SHA1withECDSA", "SHA224withECDSA", "SHA256withECDSA", "SHA384withECDSA",
				"SHA512withECDSA" };
		String[] eccKeyLengthNames = { "256-bit ECC Key", "384-bit ECC Key" };
		byte[] eccKeyPersistenceType = { (byte) 0x0C, (byte) 0x0B };
		String[] eccKeyPersistenceTypeName = { "TYPE_EC_FP_PRIVATE", "TYPE_EC_FP_PUBLIC" };

		// Set key ID '1' with ECC key
		boolean setFromMainApplet = true;
		byte keyID = (byte) 0x01;
		boolean allowProceed = true;
		Signature jceEccSignature = null;
		KeyAgreement ka = null;
		int testDataSize = 100000;
		int dataSize = testDataSize;
		byte[] parameter = null;
		byte[] data = null;
		byte[] data1 = null;
		byte[] outputCard = null;
		byte[] outputJCE = null;
		int outputCardCount = 0;
		int recvCardCount = 0;
		MessageDigest sha1 = MessageDigest.getInstance("SHA-1");

		for (int i = 0; i < eccKeyLength.length; i++) {
			// Generate ECC keypairs for Signature and KeyAgreement
			System.out.println("Generating " + eccJCEKeyLengthName[i] + " keypairs ...");
			KeyPair eccKP = generateECKeyPair(eccJCEKeyLengthName[i]);
			KeyPair ecdhKP = generateECKeyPair(eccJCEKeyLengthName[i]);
			if (eccKP == null || ecdhKP == null) {
				System.out.println("[ERR] Failed to generate keypairs ...");
				return false;
			}

			// Set key for Card side
			byte keyPersistentType;
			byte[] dataBytes;
			short keyLength;
			keyPersistentType = eccKeyPersistenceType[0];
			dataBytes = getPrivateKeyBytes(eccKP, eccKeyLength[i]);
			allowProceed = setKey(tempDev, keyID, eccKeyType[i], keyPersistentType, dataBytes,
					(short) (eccKeyLength[i] * 8), setFromMainApplet);
			System.out.println("Setting Key for [" + eccKeyLengthNames[i] + "]: " + allowProceed);

			if (allowProceed) {
				// Iterate through Cipher.MODE types
				for (int k = 0; k < cardCryptoModes.length; k++) {
					if (k == 0) {
						// Iterate through ECC signature modes to test them
						for (int j = 0; j < ecdsaCardCipherModes.length; j++) {
							// Setup card Cipher instance
							System.out.println("\r\nBegin setting crypto mode [" + cryptoModesNames[k]
									+ "] for cipher mode [" + ecdsaCardCipherModesNames[j] + "] on card...");
							boolean isCardReady = readyCrypto(tempDev, cardCryptoModes[k], ecdsaCardCipherModes[j]);
							//
							// Setup JCE Signature instance
							System.out
									.println("Begin setting crypto mode [" + ecdsaJCECipherModes[j] + "] for JCE ...");
							jceEccSignature = Signature.getInstance(ecdsaJCECipherModes[j]);

							if (isCardReady && jceEccSignature != null) {
								// Execute cipher on card

								// Setup test data
								if (data == null) {
									// Generate new data
									data = new byte[dataSize];
									rand.nextBytes(data);
								}

								// Initialize Signer with IV parameter according to cipher modes on card
								resetCrypto(tempDev, cardCryptoModes[k], keyID, null);

								// Create output buffers
								outputCard = new byte[256];
								outputJCE = null;
								outputCardCount = 0;

								System.out.println("Uploading data ...");

								// Update data chunks
								byte[] tempOutBuffer = null;
								byte[] tempInBuffer = null;
								while (outputCardCount < dataSize) {
									if ((dataSize - outputCardCount) > 248) {
										// Buffer 248 bytes and update
										tempOutBuffer = new byte[248];
										System.arraycopy(data, outputCardCount, tempOutBuffer, 0, 248);
//											System.out.println("Sending: " + BinUtils.toHexString(tempOutBuffer));
										tempInBuffer = updateCryptoData(tempDev, cardCryptoModes[k], tempOutBuffer);
//											if (tempInBuffer != null) {
//												System.out.println("Recving: " + BinUtils.toHexString(tempInBuffer));
//											}
									} else {
										// Buffer remaining bytes and finalize
										tempOutBuffer = new byte[(dataSize - outputCardCount)];
										System.arraycopy(data, outputCardCount, tempOutBuffer, 0, tempOutBuffer.length);
//											System.out.println("Sending: " + BinUtils.toHexString(tempOutBuffer));
										outputCard = doFinalCryptoData(tempDev, cardCryptoModes[k], tempOutBuffer);
//											if (outputCard != null) {
//												System.out.println("Recving: " + BinUtils.toHexString(outputCard));
//											}
									}

									// Increment tempBuffer
									outputCardCount += tempOutBuffer.length;
								}
								//
								if (allowProceed) {
									System.out.println("Finish uploading data ...");
									System.out.println("Card Result: \r\n" + BinUtils.toHexString(outputCard));

									// Execute cipher on JCE
									// Initialize Signer with according to cipher modes on JCE
									jceEccSignature.initVerify(eccKP.getPublic());

									// Cipher operation
									jceEccSignature.update(data);

									// Comparison of outputs
									if (jceEccSignature.verify(outputCard)) {
										System.out.println("[INF] ECC signature results MATCH !!!");
									} else {
										System.out.println("[ERR] ECC signature results NOT MATCH !!!");
									}

									data1 = null;
								} else {
									System.out
											.println("[ERR] Skipping comparison due to FATAL ECC operation error !!!");
									allowProceed = true;
								}
							} else {
								// Failed to initialize cipher
								System.out.println("[ERR] ECC signature initialization failed !!!");
							}
						}
					} else {
						// Iterate through ECC keyagreement modes to test them
						for (int j = 0; j < ecdhCardCipherModes.length; j++) {
							// Setup card Cipher instance
							System.out.println("\r\nBegin setting crypto mode [" + cryptoModesNames[k]
									+ "] for cipher mode [" + ecdhCardCipherModesNames[j] + "] on card...");
							boolean isCardReady = readyCrypto(tempDev, cardCryptoModes[k], ecdhCardCipherModes[j]);
							//
							// Setup JCE KeyAgreement instance
							System.out.println("Begin setting ECDH for JCE ...");

							ka = KeyAgreement.getInstance("ECDH");
							ka.init(ecdhKP.getPrivate());
							ka.doPhase(eccKP.getPublic(), true);
							byte[] hostSharedSecret = ka.generateSecret();
							sha1.reset();
							byte[] hostSHA1SharedSecret = sha1.digest(hostSharedSecret);
							System.out.println("Shared Secret: " + BinUtils.toHexString(hostSharedSecret));
							System.out
									.println("Shared Secret with SHA-1: " + BinUtils.toHexString(hostSHA1SharedSecret));

							if (isCardReady && hostSharedSecret != null) {
								// Execute ECDH on card

								// Initialize KeyAgreement with ECDHPublicKey parameter using the ecdhKP public
								// key
								resetCrypto(tempDev, cardCryptoModes[k], keyID, null);

								System.out.println("Executing ECDH keyagreement ...");

								outputCard = doFinalCryptoData(tempDev, cardCryptoModes[k],
										getPublicKeyBytes(ecdhKP, eccKeyLength[i]));
								if (outputCard != null) {
									System.out.println("Recving: " + BinUtils.toHexString(outputCard));
								}

								if (allowProceed) {
									System.out.println("Finish executing ECDH keyagreement ...");
									System.out.println("Card Result: \r\n" + BinUtils.toHexString(outputCard));

									// Comparison of outputs
									if (j == 0) {
										// ALG_EC_SVDP_DH
										if (hostSHA1SharedSecret.length == outputCard.length
												&& BinUtils.binArrayElementsCompare(outputCard, 0, hostSHA1SharedSecret,
														0, hostSHA1SharedSecret.length)) {
											System.out.println("[INF] ECDH secret results MATCH !!!");
										} else {
											System.out.println("[ERR] ECDH secret results NOT MATCH !!!");
										}
									} else {
										// ALG_EC_SVDP_DH_PLAIN
										if (hostSharedSecret.length == outputCard.length
												&& BinUtils.binArrayElementsCompare(outputCard, 0, hostSharedSecret, 0,
														hostSharedSecret.length)) {
											System.out.println("[INF] ECDH secret results MATCH !!!");
										} else {
											System.out.println("[ERR] ECDH secret results NOT MATCH !!!");
										}
									}
								} else {
									System.out
											.println("[ERR] Skipping comparison due to FATAL ECC operation error !!!");
									allowProceed = true;
								}
							} else {
								// Failed to initialize cipher
								System.out.println("[ERR] ECDH keyagreement initialization failed !!!");
							}
						}
					}
				}
				System.out.println("\r\nGetting key material ...");
				System.out.println("Key Material: " + BinUtils.toHexString(getKey(tempDev, (byte) 0x01)));
			}
		}

		return false;

	}

	public static boolean setKey(TestDevice tempDev, byte keyID, byte keyType, byte keyPersistenceType, byte[] data,
			short bitLength, boolean setFromMainApplet) throws CardException {
		boolean allowProceed = true;

		// Init key by type
		// Data layout
		// [keyLen - 2][keyType - 1][keyPersistenceType]
		if (allowProceed) {
			byte[] keyTemplate = new byte[4];
			BinUtils.shortToBytes(bitLength, keyTemplate, (short) 0);
			keyTemplate[2] = keyType;
			keyTemplate[3] = keyPersistenceType;
			System.out.println("\r\nUploading New Key ...");
			System.out.println("Key Data: " + BinUtils.toHexString(data));
			System.out.println("Key Template: " + BinUtils.toHexString(keyTemplate));
			ResponseAPDU resp = tempDev.send(new CommandAPDU((byte) 0xB0, INS_SET_KEY, P1_SET, keyID, keyTemplate));
			if (!DeviceHelper.isSuccessfulResponse(resp)) {
				System.out.println("[ERR] Setting up key template failed !!!");
				System.out.println(BinUtils.toHexString(resp.getBytes()));
				allowProceed = false;
			}
		}

		// Set key data
		// Data layout
		// [key material - kLen]
		if (allowProceed) {
			byte P1 = P1_LOAD_FROM_MAIN;
			if (!setFromMainApplet) {
				P1 = P1_LOAD_FROM_SUB;
			}
			System.out.println("P1: " + BinUtils.toHexString(new byte[] { P1 }));
			ResponseAPDU resp = tempDev.send(new CommandAPDU((byte) 0xB0, INS_SET_KEY, P1, keyID, data));
			if (!DeviceHelper.isSuccessfulResponse(resp)) {
				System.out.println("[ERR] Setting up key material failed !!!");
				System.out.println(BinUtils.toHexString(resp.getBytes()));
				allowProceed = false;
			} else {
				System.out.println("[INF] Card shows no problem in setting key material !!!");
			}
		}

		// Check if key is set
		// Scenario: Set key succeeds and key set enquiry fails ???
		if (allowProceed) {
			ResponseAPDU resp = tempDev.send(new CommandAPDU((byte) 0xB0, INS_SET_KEY, P1_IS_SET, keyID));
			if (!DeviceHelper.isSuccessfulResponse(resp)) {
				System.out.println("[ERR] Enquiring key set status failed !!!");
				System.out.println(BinUtils.toHexString(resp.getBytes()));
				allowProceed = false;
			}
		}

		return allowProceed;
	}

	public static byte[] getKey(TestDevice tempDev, byte keyID) throws CardException {
		ResponseAPDU resp = tempDev.send(new CommandAPDU((byte) 0xB0, INS_GET_KEY, (byte) 0x00, keyID, 255));
		if (DeviceHelper.isSuccessfulResponse(resp)) {
			return DeviceHelper.getSuccessfulResponseData(resp);
		} else {
			System.out.println("[ERR] Get key material failed !!!");
			System.out.println(BinUtils.toHexString(resp.getBytes()));
		}
		return null;
	}

	public static KeyPair generateECKeyPair(String algo)
			throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidAlgorithmParameterException {
		AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
		parameters.init(new ECGenParameterSpec(algo));
		java.security.spec.ECParameterSpec ecParameterSpec = parameters
				.getParameterSpec(java.security.spec.ECParameterSpec.class);
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
		keyGen.initialize(ecParameterSpec);
		KeyPair kp = keyGen.generateKeyPair();
		ECPublicKey publicKey = (ECPublicKey) kp.getPublic();
		return kp;
	}

	public static byte[] getPrivateKeyBytes(KeyPair kp, int keyLength) {
		ECPrivateKey privKey = (ECPrivateKey) kp.getPrivate();
		byte[] s = privKey.getS().toByteArray();
		byte[] outFormattedPrivKey = new byte[keyLength];
		if (s.length > keyLength) {
			System.arraycopy(s, 1, outFormattedPrivKey, 0, keyLength);
		} else if (s.length < keyLength) {
			System.arraycopy(s, 0, outFormattedPrivKey, keyLength - s.length, s.length);
		} else {
			System.arraycopy(s, 0, outFormattedPrivKey, 0, keyLength);
		}
		return outFormattedPrivKey;
	}

	public static byte[] getPublicKeyBytes(KeyPair kp, int keyLength) {
		byte[] outFormattedPubKey = new byte[1 + (2 * keyLength)];
		int cursor = 0;
		int copy = 0;
		outFormattedPubKey[cursor] = (byte) 0x04;
		cursor++;

		// Handle key material via key length checking
		byte[] X = ((ECPublicKey) kp.getPublic()).getW().getAffineX().toByteArray();
		if (X.length > keyLength) {
			copy = 1;
			System.arraycopy(X, copy, outFormattedPubKey, cursor, keyLength);
		} else if (X.length < keyLength) {
			copy = keyLength - X.length;
			System.arraycopy(X, 0, outFormattedPubKey, cursor + copy, X.length);
		} else {
			System.arraycopy(X, copy, outFormattedPubKey, cursor, keyLength);
		}
		cursor += keyLength;
		copy = 0;

		byte[] Y = ((ECPublicKey) kp.getPublic()).getW().getAffineY().toByteArray();
		if (Y.length > keyLength) {
			copy = 1;
			System.arraycopy(Y, copy, outFormattedPubKey, cursor, keyLength);
		} else if (Y.length < keyLength) {
			copy = keyLength - Y.length;
			System.arraycopy(Y, 0, outFormattedPubKey, cursor + copy, Y.length);
		} else {
			System.arraycopy(Y, copy, outFormattedPubKey, cursor, keyLength);
		}
		cursor = 0;
		copy = 0;

		return outFormattedPubKey;
	}

	public static void uploadArbitraryDataChunk(TestDevice tempDev, byte[] data) throws CardException {
		ResponseAPDU resp = tempDev
				.send(new CommandAPDU((byte) 0xB0, INS_SET_DATA, P1_LOAD_FROM_MAIN, (byte) 0x00, data));
		if (!DeviceHelper.isSuccessfulResponse(resp)) {
			System.out.println("[ERR] Uploading arbitrary data failed !!!");
			System.out.println(BinUtils.toHexString(resp.getBytes()));
		}
	}
//
//	public static int getArbitraryDataSize(TestDevice tempDev) throws CardException {
//		ResponseAPDU resp = tempDev.send(new CommandAPDU((byte) 0xB0, INS_SET_DATA, P1_IS_SET, (byte) 0x00, 255));
//		if (DeviceHelper.isSuccessfulResponse(resp)) {
//			byte[] respData = DeviceHelper.getSuccessfulResponseData(resp);
//			if (respData.length == 2) {
//				return BinUtils.bytesToShort(respData[0], respData[1]);
//			} else {
//				System.out.println("[ERR] Invalid arbitrary data length !!!");
//				System.out.println(BinUtils.toHexString(resp.getBytes()));
//			}
//		} else {
//			System.out.println("[ERR] Failed to get arbitrary data length !!!");
//			System.out.println(BinUtils.toHexString(resp.getBytes()));
//		}
//		return -1;
//	}

	public static byte[] downloadArbitraryDataChunk(TestDevice tempDev) throws CardException {
//		byte[] data = new byte[4];
//		BinUtils.shortToBytes((short) off, data, (short) 0);
//		BinUtils.shortToBytes((short) len, data, (short) 2);
		ResponseAPDU resp = tempDev.send(new CommandAPDU((byte) 0xB0, INS_SET_DATA, P1_GET, (byte) 0x00, 255));
		if (DeviceHelper.isSuccessfulResponse(resp)) {
			return DeviceHelper.getSuccessfulResponseData(resp);
		} else {
			System.out.println("[ERR] Hash finalization failed !!!");
			System.out.println(BinUtils.toHexString(resp.getBytes()));
		}
		return null;
	}

	@Override
	public String getPluginName() {
		return pluginName;
	}

	@Override
	public String getPluginDescription() {
		return shortDescription;
	}

}
