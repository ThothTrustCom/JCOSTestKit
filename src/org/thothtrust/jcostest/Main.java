package org.thothtrust.jcostest;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Scanner;
import java.util.logging.Level;
import javax.smartcardio.*;
import org.thothtrust.jcostest.log.LogManager;
import org.thothtrust.jcostest.process.extension.TestFunctionService;

import interfaces.TestDevice;
public class Main extends ClassLoader {

	public static final String systPropsFileName = "system.properties";
	public static Scanner sc = null;
	public static Console console = null;
	public static Thread consoleThread = null;
	public static Thread wsThread = null;
	public static Thread rdThread = null;
	public static TestDevice selectedDev = null;	

	public static void main(String[] args) {
		LogManager.init();
		LogManager.setLogLevel("FINE");
		try {
			loadEssentials();
			loadConsole();		
		} catch (Exception e) {
			e.printStackTrace();
		}
		LogManager.close();
	}

	public static void loadEssentials() throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException,
			InvalidParameterSpecException, SignatureException, Exception {
		sc = new Scanner(System.in);
		
		// Start plugin loading
		TestFunctionService.getInstance().loadPlugins();
	}

	public static void loadConsole() {
		console = new Console(sc);
		consoleThread = new Thread(console);
        consoleThread.start(); 
	}
	
	public static void shutdown() {
		LogManager.log("Exit JCOS Testing System");
		System.exit(0);
	}
	
	public static TestDevice getSelectedDev() {
		return selectedDev;
	}

	public static void setSelectedDev(TestDevice selectedDev) {
		Main.selectedDev = selectedDev;
	}
}