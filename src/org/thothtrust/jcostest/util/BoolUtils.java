package org.thothtrust.jcostest.util;

import org.thothtrust.jcostest.Constants;

public class BoolUtils {

	public static byte boolToByte(boolean bool) {
		if (bool)
			return Constants.BB_TRUE;
		else
			return Constants.BB_FALSE;
	}

	public static boolean byteToBool(byte b) {
		if (b == (byte) 0x01)
			return true;
		else
			return false;
	}

}
