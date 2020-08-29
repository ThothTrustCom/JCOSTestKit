package plugin;

import java.util.HashMap;

import interfaces.BinUtils;
import interfaces.TestDevice;
import interfaces.TestFunctionInterface;

public class DefaultPlugin implements TestFunctionInterface {
	
	String pluginName = "Default Test Plugin";
	String shortDescription = "Default test plugin for JCOS test kit.";

	@Override
	public HashMap<String, Object> process(TestDevice device) {
		System.out.println("Device's ATR: " + BinUtils.toHexString(device.getATRBytes()));
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
