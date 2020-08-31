package jcostest;

import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.DESKey;
import javacard.security.DSAPrivateKey;
import javacard.security.DSAPublicKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.Key;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;

public class AlternateKM {

	public static boolean setKey(Key key, byte[] keyData, byte[] paramData, short[] off, short[] len) {
		if (key instanceof AESKey) {
			((AESKey) key).setKey(keyData, off[0]);
		} else if (key instanceof DESKey) {
			((DESKey) key).setKey(keyData, off[0]);
		} else if (key instanceof DSAPublicKey) {
			((DSAPublicKey) key).setG(paramData, off[0], len[0]);
			((DSAPublicKey) key).setP(paramData, off[1], len[1]);
			((DSAPublicKey) key).setQ(paramData, off[2], len[2]);
			((DSAPublicKey) key).setY(keyData, off[3], len[3]);
		} else if (key instanceof DSAPrivateKey) {
			((DSAPrivateKey) key).setG(paramData, off[0], len[0]);
			((DSAPrivateKey) key).setP(paramData, off[1], len[1]);
			((DSAPrivateKey) key).setQ(paramData, off[2], len[2]);
			((DSAPrivateKey) key).setX(keyData, off[3], len[3]);
		} else if (key instanceof ECPublicKey) {
			((ECPublicKey) key).setA(keyData, off[0], len[0]);
			((ECPublicKey) key).setB(keyData, off[1], len[1]);
			((ECPublicKey) key).setFieldFP(keyData, off[2], len[2]);
			((ECPublicKey) key).setG(keyData, off[3], len[3]);
			((ECPublicKey) key).setR(keyData, off[4], len[4]);			
			((ECPublicKey) key).setW(keyData, off[5], len[5]);
			((ECPublicKey) key).setK((short) (keyData[off[6]] & 0xFF));
		} else if (key instanceof ECPrivateKey) {
			((ECPrivateKey) key).setA(keyData, off[0], len[0]);
			((ECPrivateKey) key).setB(keyData, off[1], len[1]);
			((ECPrivateKey) key).setFieldFP(keyData, off[2], len[2]);
			((ECPrivateKey) key).setG(keyData, off[3], len[3]);
			((ECPrivateKey) key).setR(keyData, off[4], len[4]);			
			((ECPrivateKey) key).setS(keyData, off[5], len[5]);
		} else if (key instanceof RSAPublicKey) {
			((RSAPublicKey) key).setModulus(keyData, off[0], len[0]);
			((RSAPublicKey) key).setExponent(keyData, off[1], len[1]);
		} else if (key instanceof RSAPrivateKey) {
			((RSAPrivateKey) key).setModulus(keyData, off[0], len[0]);
			((RSAPrivateKey) key).setExponent(keyData, off[1], len[1]);
		} else {
			return false;
		}
		return true;
	}
	
	public static void setData(byte[] sourceData, short sOff, byte[] targetData, short tOff, short len) {
		Util.arrayCopy(sourceData, sOff, targetData, tOff, len);
	}
}
