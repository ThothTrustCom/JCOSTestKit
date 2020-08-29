package org.thothtrust.jcostest.log;

import java.io.File;
import java.io.IOException;
import java.util.Date;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

public class LogManager {
	private static FileHandler log = null;
	private static SimpleFormatter logFormat = null;
	private static String logFolder = "logs";
	private static String logPath = "server.log";
	private static Logger logger = null;
	private static int logSize = 10485760;
	private static int logRotation = 1000;

	public static void init() {
		try {
			File logFolderPath = new File(logFolder);
			if (!logFolderPath.exists()) {
				logFolderPath.mkdir();
			}
			log = new FileHandler(logFolderPath.getPath() + "/" + logPath, logSize, logRotation, true);
			logFormat = new SimpleFormatter() {
				private static final String format = "[%1$tF %1$tT] [%2$-7s] %3$s %n";

				@Override
				public synchronized String format(LogRecord lr) {
					return String.format(format, new Date(lr.getMillis()), lr.getLevel().getLocalizedName(),
							lr.getMessage());
				}
			};
			log.setFormatter(logFormat);
			logger = Logger.getAnonymousLogger();
			logger.setLevel(Level.FINEST);
			logger.addHandler(log);
			logger.setUseParentHandlers(false);
		} catch (IOException | SecurityException ex) {
			Logger.getLogger(LogManager.class.getName()).log(Level.SEVERE, null, ex);
		}
	}

	public static void log(String logText) {
		log(Level.INFO, logText, true);
	}

	public static void log(Level logLevel, String logText) {
		log(logLevel, logText, true);
	}

	public static void log(Level logLevel, String logText, boolean print) {
		String lvText = "";
		logger.log(logLevel, logText);
		log.flush();
		if (print) {
			switch (logLevel.getName()) {
			case "SEVERE":
				lvText = "ERR";
				break;
			case "WARNING":
				lvText = "WRN";
				break;
			default:
				lvText = "INF";
				break;
			}
			if (logger.getLevel().intValue() <= logLevel.intValue()) {
				System.out.println("[" + lvText + "] " + logText);
			}
		}
	}

	public static void log(Level logLevel, String logText, Exception ex) {
		logger.log(logLevel, logText, ex);
		log.flush();
	}

	public static void err(Exception ex) {
		err("", ex, true);
	}

	public static void err(String logText, Exception ex, boolean print) {
		logger.log(Level.SEVERE, logText, ex);
		if (print) {
			System.out.println("[ERR] " + logText);
		}
		log.flush();
	}

	public static void close() {
		log.close();
	}

	public static void setLogLevel(String logLevel) {
		if (logLevel.equalsIgnoreCase("INFO")) {
			logger.setLevel(Level.INFO);
		} else if (logLevel.equalsIgnoreCase("ALL")) {
			logger.setLevel(Level.ALL);
		} else if (logLevel.equalsIgnoreCase("CONFIG")) {
			logger.setLevel(Level.CONFIG);
		} else if (logLevel.equalsIgnoreCase("FINE")) {
			logger.setLevel(Level.FINE);
		} else if (logLevel.equalsIgnoreCase("FINER")) {
			logger.setLevel(Level.FINER);
		} else if (logLevel.equalsIgnoreCase("FINEST")) {
			logger.setLevel(Level.FINEST);
		} else if (logLevel.equalsIgnoreCase("OFF")) {
			logger.setLevel(Level.OFF);
		} else if (logLevel.equalsIgnoreCase("SEVERE")) {
			logger.setLevel(Level.SEVERE);
		} else if (logLevel.equalsIgnoreCase("WARNING")) {
			logger.setLevel(Level.WARNING);
		} else {
			logger.setLevel(Level.INFO);
		}
	}
}
