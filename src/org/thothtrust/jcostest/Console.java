package org.thothtrust.jcostest;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Scanner;

import javax.smartcardio.CardException;

import org.thothtrust.jcostest.log.LogManager;
import org.thothtrust.jcostest.process.extension.TestFunctionService;
import org.thothtrust.jcostest.sc.DeviceManager;
import org.thothtrust.jcostest.util.BinUtils;

import interfaces.TestDevice;
import interfaces.TestFunctionInterface;

public class Console implements Runnable {
	Scanner sc = null;
	DeviceManager dm = null;
	TestFunctionService testServ = null;
	static volatile boolean runConsole = true;
	static volatile boolean isRequestInput = true;

	public Console(Scanner sc) {
		this.sc = sc;
	}

	public void init() throws Exception {
		dm = DeviceManager.getInstance();
		testServ = TestFunctionService.getInstance();
		mainMenu();
	}

	public void run() {
		try {
			init();
		} catch (Exception e) {
			LogManager.err(e);
			e.printStackTrace();
		}
	}

	public void mainMenu() throws Exception {
		printBanner();
		while (runConsole) {
			while (isRequestInput) {
				requestInput();
			}
		}
	}

	public void printBanner() {
		System.out.println("===============================");
		System.out.println("# ~~ JCOS Test Kit Console ~~ #");
		System.out.println("===============================");
		System.out.println("version 1.0.0");
		System.out.println("Type 'help', 'h' or '?' to show help (without the quotation marks).\r\n");
	}

	public void showConsoleHelp() {
		System.out.println("Help Menu");
		System.out.println("---------");
		System.out.println("Options:                    Description:");
		System.out.println("help, h, ?                  Print help");
		System.out.println("quit, exit, bye             Terminates Broker and ALL services");
		System.out.println("listcards                   List cards");
		System.out.println("setcard                     Set target card");
		System.out.println("listtestmods                List test modules");
		System.out.println("runtests                    Run test sequences");
		System.out.println("");
	}

	public void requestInput() throws Exception {
		isRequestInput = false;
		System.out.print(">: ");
		parseCommand(sc.nextLine());
	}

	public void parseCommand(String input) throws Exception {
		switch (input) {
		case "exit":
			Main.shutdown();
			break;
		case "quit":
			Main.shutdown();
			break;
		case "bye":
			Main.shutdown();
			break;
		case "h":
			showConsoleHelp();
			break;
		case "?":
			showConsoleHelp();
			break;
		case "help":
			showConsoleHelp();
			break;
		case "listcards":
			showCardsList();
			break;
		case "setcard":
			setCard();
			break;
		case "listtestmods":
			listTestModules();
			break;
		case "runtests":
			runTests();
			break;
		default:
			System.out.println("No such command");
			break;
		}
		isRequestInput = true;
	}

	public void showCardsList() throws CardException {
		int cnt = dm.getDevicesCount();
		System.out.println("Test Applets Instances: " + cnt + "\r\n");
		int i = 0;
		for (TestDevice dev : dm.getDevices()) {
			System.out.print("Instance: " + i);
			if (Main.getSelectedDev() != null) {
				if (Main.getSelectedDev().getTerminalName().equals(dev.getTerminalName())) {
					System.out.print(" [Default]");
				}
			}
			System.out.println("");
			System.out.println("Termainl: " + dev.getTerminalName());
			System.out.println("ATR     : " + BinUtils.toHexString(dev.getATRBytes()));
			System.out.println("");
			i++;
		}
	}

	public void setCard() {
		System.out.print("Enter instance position: ");
		try {
			int pos = Integer.valueOf(sc.nextLine().trim());
			if (pos < dm.getDevicesCount()) {
				Main.setSelectedDev(dm.getDevice(pos));
				System.out.println(
						"Device with terminal [" + Main.getSelectedDev().getTerminalName() + "] selected ...\r\n");
			}
		} catch (NumberFormatException ex) {
			System.out.println("Invalid instance position ...");
			System.out.println("Failed setting testing device ...\r\n");
		}
	}

	public void listTestModules() {
		int cnt = testServ.getPlugins().size();
		System.out.println("Test Plugins: " + cnt + "\r\n");
		int i = 0;
		for (TestFunctionInterface plugin : testServ.getPlugins()) {
			System.out.println("Plugin Pos : " + i);
			System.out.println("Plugin Name: " + plugin.getPluginName());
			System.out.println("Description: " + plugin.getPluginDescription());
			System.out.println("");
			i++;
		}
	}

	public void runTests() {
		if (Main.getSelectedDev() == null) {
			System.out.println("No selected device for testing ...\r\n");
			return;
		}

		System.out.println("Enter plugins' position running sequence separated by commas: ");
		String sequenceStr = sc.nextLine();
		int i = 0;
		String[] posSequenceStrElements = sequenceStr.trim().split(",");
		for (String ele : posSequenceStrElements) {
			try {
				Integer.valueOf(ele);
			} catch (NumberFormatException ex) {
				System.out.println("Invalid position number ...");
				System.out.println("Failed running test ...\r\n");
				return;
			}
		}
		int[] pos = new int[posSequenceStrElements.length];
		for (String ele : posSequenceStrElements) {
			int pluginPos = Integer.valueOf(ele);
			boolean hasDuplicate = false;
			// Check for duplicates
			for (int j = 0; j < pos.length; j++) {
				if (pos[j] == pluginPos) {
					hasDuplicate = true;
					break;
				}
			}

			if (!hasDuplicate) {
				pos[i] = pluginPos;
				i++;
			}
		}
		System.out.println("Executing " + i + " plugins ...\r\n");
		for (int executingPos : pos) {
			System.out.println("Executing plugin pos: " + executingPos);
			TestFunctionInterface tfi = testServ.findLoadedPluginByPos(executingPos);
			if (tfi != null) {
				parseResult(tfi.process(Main.getSelectedDev()));
			}
		}
		System.out.println("");
	}

	public boolean isConsoleRunning() {
		return runConsole;
	}

	public void stopConsole() {
		runConsole = false;
	}

	public static void reenableInput() {
		isRequestInput = true;
	}

	public static void parseResult(HashMap<String, Object> result) {
		String navail = "Not Available";
		String errorExec = "Error";
		String failExec = "Fail";
		String okExec = "OK";
		String unknown = "Unknown";
		if (result != null) {
			int longestStrLen = 0;
			Iterator it = result.entrySet().iterator();
			while (it.hasNext()) {
				Map.Entry elements = (Map.Entry) it.next();
				String key = (String) elements.getKey();
				if (key.length() > longestStrLen) {
					longestStrLen = key.length();
				}
			}
			
			it = result.entrySet().iterator();
			System.out.println("");
			while (it.hasNext()) {
				Map.Entry elements = (Map.Entry) it.next();
				System.out.print(elements.getKey().toString());
				if (elements.getKey().toString().length() < longestStrLen) {
					for (int i = 0; i < longestStrLen - elements.getKey().toString().length(); i++) {
						System.out.print(" ");
					}
				}
				System.out.print("   ");
				if ((int) elements.getValue() == -2) {
					System.out.print(errorExec);
				} else if ((int) elements.getValue() == -1) {
					System.out.print(navail);
				} else if ((int) elements.getValue() == 0) {
					System.out.print(failExec);
				} else if ((int) elements.getValue() == 1) {
					System.out.print(okExec);
				} else {
					System.out.print(unknown);
				}
				System.out.println("");
			}
		}
	}
}
