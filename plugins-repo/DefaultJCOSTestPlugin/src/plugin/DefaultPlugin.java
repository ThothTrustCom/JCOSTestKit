package plugin;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;

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
	public static String[] hashAlgoJCE = { "MD5", "RIPEMD160", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512" };
	public static byte[] hashAlgoJC = { ALG_MD5, ALG_RIPEMD160, ALG_SHA, ALG_SHA_224, ALG_SHA_256, ALG_SHA_384,
			ALG_SHA_512 };
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

	@Override
	public HashMap<String, Object> process(TestDevice device) {
		try {
			System.out.println("Device's ATR: " + BinUtils.toHexString(device.getATRBytes()));

			System.out.println("Begin overload test ...");
			int messageLen = 100000;
			byte[] message = new byte[messageLen];
			SecureRandom rand = new SecureRandom();
			rand.nextBytes(message);

			// Display Message
			System.out.println("Message Length: " + message.length + " bytes");
//			System.out.println("Message Data: " + BinUtils.toHexString(message));

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
			
			// Arbitrary data upload and download test
			System.out.println("Begin arbitrary upload and download via static class test ...");
			messageLen = 255;
			message = new byte[messageLen];
			rand.nextBytes(message);
			System.out.println("Message Length: " + message.length + " bytes");
			System.out.println("Data to upload: \r\n" + BinUtils.toHexString(message));
			
			uploadArbitraryDataChunk(device, message);
			
			int arbitraryDataSize = getArbitraryDataSize(device);
			System.out.println("On-Card Arbitrary Data Length: " + arbitraryDataSize + " bytes");
			
			if (arbitraryDataSize == messageLen) {
				byte[] downloadData = downloadArbitraryDataChunk(device, 0, messageLen);
				System.out.println("Data download: \r\n" + BinUtils.toHexString(downloadData));
				System.out.println("Data are same ? " + BinUtils.binArrayElementsCompare(message, 0, downloadData, 0, messageLen));				
			} else {
				System.out.println("Failed to upload arbitrary data onto card via static class ...");
			}
		} catch (CardException | NoSuchAlgorithmException e) { //
			e.printStackTrace();
		}
		return null;
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

	public static void uploadArbitraryDataChunk(TestDevice tempDev, byte[] data) throws CardException {
		ResponseAPDU resp = tempDev.send(new CommandAPDU((byte) 0xB0, INS_SET_DATA, P1_SET, P2_PART_SUB, data));
		if (!DeviceHelper.isSuccessfulResponse(resp)) {
			System.out.println("[ERR] Uploading arbitrary data failed !!!");
			System.out.println(BinUtils.toHexString(resp.getBytes()));
		}
	}

	public static int getArbitraryDataSize(TestDevice tempDev) throws CardException {
		ResponseAPDU resp = tempDev.send(new CommandAPDU((byte) 0xB0, INS_SET_DATA, P1_IS_SET, (byte) 0x00, 4));
		if (DeviceHelper.isSuccessfulResponse(resp)) {
			byte[] respData = DeviceHelper.getSuccessfulResponseData(resp);
			if (respData.length == 2) {
				return BinUtils.bytesToShort(respData[0], respData[1]);
			}
		} else {
			System.out.println("[ERR] Hash finalization failed !!!");
			System.out.println(BinUtils.toHexString(resp.getBytes()));
		}
		return -1;
	}

	public static byte[] downloadArbitraryDataChunk(TestDevice tempDev, int off, int len) throws CardException {
		byte[] data = new byte[4];
		BinUtils.shortToBytes((short) off, data, (short) 0);
		BinUtils.shortToBytes((short) len, data, (short) 2);
		ResponseAPDU resp = tempDev.send(new CommandAPDU((byte) 0xB0, INS_SET_DATA, P1_GET, (byte) 0x00, data, 255));
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
