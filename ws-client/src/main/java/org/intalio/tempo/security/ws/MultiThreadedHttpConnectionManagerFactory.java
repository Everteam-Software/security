package org.intalio.tempo.security.ws;

import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.commons.httpclient.params.HttpConnectionManagerParams;


public class MultiThreadedHttpConnectionManagerFactory {
	private static MultiThreadedHttpConnectionManager connectionManager = null;
	private static Object LOCK = new Object(); 

	private MultiThreadedHttpConnectionManagerFactory() {
	} 

	public static MultiThreadedHttpConnectionManager getInstance() {
		if (connectionManager == null) {
			synchronized (LOCK) {
				if (connectionManager == null) {
					connectionManager = new MultiThreadedHttpConnectionManager();
					HttpConnectionManagerParams params = new HttpConnectionManagerParams();
					params.setDefaultMaxConnectionsPerHost(2);
					params.setSoTimeout(120 * 1000);
					connectionManager.setParams(params);
				}
			}
		}
		return connectionManager;
	}
}
