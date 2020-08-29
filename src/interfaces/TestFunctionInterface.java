package interfaces;

import java.util.HashMap;

public interface TestFunctionInterface {
	
	public HashMap<String, Object> process(TestDevice device);

	public String getPluginName();

	public String getPluginDescription();
}