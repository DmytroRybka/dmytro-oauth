package com.google.code.samples.xoauth;

import java.security.Security;
import java.util.Properties;

import javax.mail.Folder;
import javax.mail.MessagingException;
import javax.mail.Session;

import junit.framework.TestCase;

import com.sun.mail.imap.IMAPSSLStore;

public class TwoLeggedLoginTest extends TestCase {
	
	//yea.. not cool to fix constants here... but for testing okay...
	String USER_EMAIL = ""; //e.g. user@mydomain.com
	String OAUTH_KEY = ""; //e.g. mydomain.com
	String OAUTH_SECRET = ""; //e.g. aidjfi939fj823j
	
	
	public void testTwoLeggedLogin() throws MessagingException {
		
		
		   Security.addProvider(new XoauthAuthenticator.XoauthProvider());
	                       
	        String host = "imap.gmail.com";
	        int port = 993;
	        
	        Properties props = new Properties();
	        props.put("mail.imaps.sasl.enable", "true");
	        props.put("mail.imaps.sasl.mechanisms", "XOAUTH");
	        
	        props.put(XoauthSaslClientFactory.CONSUMER_KEY_PROP,
	        		OAUTH_KEY);  
	        props.put(XoauthSaslClientFactory.CONSUMER_SECRET_PROP,
	        		OAUTH_SECRET);
	        
	        props.put(XoauthSaslClientFactory.OAUTH_TWO_LEGGED_ENABLED,
	                "true");  
	        
	        props.put(XoauthSaslClientFactory.OAUTH_TWO_LEGGED_EMAIL,
	        		USER_EMAIL);
	        
	        
	        
	        Session session = Session.getInstance(props);
	        session.setDebug(true);

	        IMAPSSLStore store = new IMAPSSLStore(session, null);
	        store.connect(host, port, USER_EMAIL, "");
	        
	        Folder defaultfolder = store.getDefaultFolder();
	        
	        assertNotNull(defaultfolder);
	        System.out.println("got default folder: " + defaultfolder.getFullName());

		
	}
}
