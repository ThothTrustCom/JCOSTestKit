package jcostest;

import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.DESKey;
import javacard.security.DSAPrivateKey;
import javacard.security.DSAPublicKey;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.Key;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;

public class AlternateKM {

	public static boolean setKey(Key key, byte keyType, byte[] keyData, short kOff, short kLen) {
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

	public static void initECCurveParameters(Key key, byte keyType) {
		if (keyType == JCOSTestApplet.KEY_EC_SECP_256_R1) {
			((ECKey) key).setA(Constants.ansix9p256r1_a, (short) 0, (short) Constants.ansix9p256r1_a.length);
			((ECKey) key).setB(Constants.ansix9p256r1_b, (short) 0, (short) Constants.ansix9p256r1_b.length);
			((ECKey) key).setFieldFP(Constants.ansix9p256r1_field, (short) 0,
					(short) Constants.ansix9p256r1_field.length);
			((ECKey) key).setG(Constants.ansix9p256r1_g, (short) 0, (short) Constants.ansix9p256r1_g.length);
			((ECKey) key).setR(Constants.ansix9p256r1_r, (short) 0, (short) Constants.ansix9p256r1_r.length);
			((ECKey) key).setK((short) 1);
		} else if (keyType == JCOSTestApplet.KEY_EC_SECP_384_R1) {
			((ECKey) key).setA(Constants.ansix9p384r1_a, (short) 0, (short) Constants.ansix9p384r1_a.length);
			((ECKey) key).setB(Constants.ansix9p384r1_b, (short) 0, (short) Constants.ansix9p384r1_b.length);
			((ECKey) key).setFieldFP(Constants.ansix9p384r1_field, (short) 0,
					(short) Constants.ansix9p384r1_field.length);
			((ECKey) key).setG(Constants.ansix9p384r1_g, (short) 0, (short) Constants.ansix9p384r1_g.length);
			((ECKey) key).setR(Constants.ansix9p384r1_r, (short) 0, (short) Constants.ansix9p384r1_r.length);
			((ECKey) key).setK((short) 1);
		} else if (keyType == JCOSTestApplet.KEY_EC_SECP_521_R1) {
			((ECKey) key).setA(Constants.ansix9p521r1_a, (short) 0, (short) Constants.ansix9p521r1_a.length);
			((ECKey) key).setB(Constants.ansix9p521r1_b, (short) 0, (short) Constants.ansix9p521r1_b.length);
			((ECKey) key).setFieldFP(Constants.ansix9p521r1_field, (short) 0,
					(short) Constants.ansix9p521r1_field.length);
			((ECKey) key).setG(Constants.ansix9p521r1_g, (short) 0, (short) Constants.ansix9p521r1_g.length);
			((ECKey) key).setR(Constants.ansix9p521r1_r, (short) 0, (short) Constants.ansix9p521r1_r.length);
			((ECKey) key).setK((short) 1);
		} else if (keyType == JCOSTestApplet.KEY_EC_SECP_256_K1) {
			((ECKey) key).setA(Constants.SECP256K1_A, (short) 0, (short) Constants.SECP256K1_A.length);
			((ECKey) key).setB(Constants.SECP256K1_B, (short) 0, (short) Constants.SECP256K1_B.length);
			((ECKey) key).setFieldFP(Constants.SECP256K1_FIELD, (short) 0, (short) Constants.SECP256K1_FIELD.length);
			((ECKey) key).setG(Constants.SECP256K1_G, (short) 0, (short) Constants.SECP256K1_G.length);
			((ECKey) key).setR(Constants.SECP256K1_R, (short) 0, (short) Constants.SECP256K1_R.length);
			((ECKey) key).setK((short) 1);
		} else if (keyType == JCOSTestApplet.KEY_EC_BRAINPOOL_256_R1) {
			((ECKey) key).setA(Constants.brainpoolP256r1_a, (short) 0, (short) Constants.brainpoolP256r1_a.length);
			((ECKey) key).setB(Constants.brainpoolP256r1_b, (short) 0, (short) Constants.brainpoolP256r1_b.length);
			((ECKey) key).setFieldFP(Constants.brainpoolP256r1_field, (short) 0,
					(short) Constants.brainpoolP256r1_field.length);
			((ECKey) key).setG(Constants.brainpoolP256r1_g, (short) 0, (short) Constants.brainpoolP256r1_g.length);
			((ECKey) key).setR(Constants.brainpoolP256r1_r, (short) 0, (short) Constants.brainpoolP256r1_r.length);
			((ECKey) key).setK((short) 1);
		} else if (keyType == JCOSTestApplet.KEY_EC_BRAINPOOL_384_R1) {
			((ECKey) key).setA(Constants.brainpoolP384r1_a, (short) 0, (short) Constants.brainpoolP384r1_a.length);
			((ECKey) key).setB(Constants.brainpoolP384r1_b, (short) 0, (short) Constants.brainpoolP384r1_b.length);
			((ECKey) key).setFieldFP(Constants.brainpoolP384r1_field, (short) 0,
					(short) Constants.brainpoolP384r1_field.length);
			((ECKey) key).setG(Constants.brainpoolP384r1_g, (short) 0, (short) Constants.brainpoolP384r1_g.length);
			((ECKey) key).setR(Constants.brainpoolP384r1_r, (short) 0, (short) Constants.brainpoolP384r1_r.length);
			((ECKey) key).setK((short) 1);
		} else if (keyType == JCOSTestApplet.KEY_EC_BRAINPOOL_512_R1) {
			((ECKey) key).setA(Constants.brainpoolP512r1_a, (short) 0, (short) Constants.brainpoolP512r1_a.length);
			((ECKey) key).setB(Constants.brainpoolP512r1_b, (short) 0, (short) Constants.brainpoolP512r1_b.length);
			((ECKey) key).setFieldFP(Constants.brainpoolP512r1_field, (short) 0,
					(short) Constants.brainpoolP512r1_field.length);
			((ECKey) key).setG(Constants.brainpoolP512r1_g, (short) 0, (short) Constants.brainpoolP512r1_g.length);
			((ECKey) key).setR(Constants.brainpoolP512r1_r, (short) 0, (short) Constants.brainpoolP512r1_r.length);
			((ECKey) key).setK((short) 1);
		}
	}
	
	public static void setData(byte[] sourceData, short sOff, byte[] targetData, short tOff, short len) {
		Util.arrayCopy(sourceData, sOff, targetData, tOff, len);
	}
}
