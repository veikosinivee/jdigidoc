/*
 * PKCS11SignatureFactory.java
 * PROJECT: JDigiDoc
 * DESCRIPTION: Digi Doc functions for creating
 *	and reading signed documents. 
 * AUTHOR:  Veiko Sinivee, Sunset Software OÜ
 *==================================================
 * Copyright (C) AS Sertifitseerimiskeskus
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * GNU Lesser General Public Licence is available at
 * http://www.gnu.org/copyleft/lesser.html
 *==================================================
 */

package ee.sk.digidoc.factory;
import ee.sk.digidoc.Base64Util;
import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.Signature;
import ee.sk.digidoc.SignedDoc;
//import ee.sk.digidoc.SignedDoc;
import java.security.*; 
import java.security.cert.*; 

import iaik.pkcs.pkcs11.*; 
import iaik.pkcs.pkcs11.objects.*; 
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import ee.sk.utils.ConfigManager;
import ee.sk.utils.ConvertUtils;

import java.io.IOException;
//import java.io.File;
import java.io.ByteArrayInputStream;
import java.util.Vector;
import org.apache.log4j.Logger;
import ee.sk.digidoc.TokenKeyInfo;


/**
 * PKCS#11 based signature implementation
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class PKCS11SignatureFactory implements SignatureFactory 
{
    /** Object represent a current PKCS#11 module. */
    private Module m_pkcs11Module;
    /** An array of available tokens. */
    private TokenKeyInfo[] m_tokens;
    /** A current session object are used to perform cryptographic operations on a token. */
    private Session m_currentSession;
    /** selected (current token) */
    private TokenKeyInfo m_selToken;
    /** security provider */
    private Provider m_secProvider;
	/** log4j logger */
    private static Logger m_logger = Logger.getLogger(PKCS11SignatureFactory.class);
    /** PKCS#11 module  is initialized */
    private static boolean m_isInitialized;


    /** Creates new PKCS11SignatureFactory */
    public PKCS11SignatureFactory() {
        m_pkcs11Module = null;
        m_tokens = null;
		m_currentSession = null;
		m_selToken = null;
		m_secProvider = null;
        m_isInitialized = false;
    }
    
    /** 
     * initializes the implementation class  
     */
    public void init()
        throws DigiDocException
    {
        if(m_pkcs11Module == null)
            initPKCS11();
        if(m_secProvider == null)
            initProvider();
    }   
    

    /** 
     * initializes the PKCS#11 subsystem  
     */
    public void initPKCS11()
        throws DigiDocException
    {
       try {
       		if(m_logger.isInfoEnabled())
       			m_logger.info("Loading PKCS11 driver: " + ConfigManager.
                     instance().getProperty("DIGIDOC_SIGN_PKCS11_DRIVER") +
                     " libpath: " + System.getProperty("java.library.path"));
            // load PKCS11 module
            m_pkcs11Module = (Module)AccessController.doPrivileged(
                new PrivilegedExceptionAction()  {
                    public java.lang.Object run() throws IOException {
                        String moduleName = ConfigManager.
                            instance().getProperty("DIGIDOC_SIGN_PKCS11_DRIVER");
                        Module m = Module.getInstance(moduleName);
                        return m;
                    }
                }
            );
            try {
              if (!m_isInitialized) {
            	m_pkcs11Module.initialize(null); // initializes the module
            	m_isInitialized = true;
              }
            } catch(iaik.pkcs.pkcs11.wrapper.PKCS11Exception ex) {
            	m_logger.error("Pkcs11 error: " + ex);
            	if(ex.getErrorCode() == PKCS11Constants.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
            		m_logger.error("PKCS11 already loaded ok");
            		m_isInitialized = true;
            	} else
            		DigiDocException.handleException(ex, DigiDocException.ERR_CRYPTO_DRIVER);
            }
            
            // read all token info
            m_tokens = getTokenKeys();
        } catch(Exception e) {
            m_pkcs11Module = null; // reset since we had an error
            DigiDocException.handleException(e, DigiDocException.ERR_CRYPTO_DRIVER);
        }
        if((m_tokens == null) || (m_tokens.length == 0)) 
            throw new DigiDocException(DigiDocException.ERR_PKCS11_INIT,
                "Error reading signature certificates from card!", null);
    }
    
    /**
     * Reads all useable token keys
     * @return list of available token/key info
     * @throws DigiDocException
     */
    public TokenKeyInfo[] getTokenKeys()
    	throws DigiDocException
    {
    	Vector vec = new Vector();
    	Session sess = null;
    	try {
    	  CertificateFactory certFac = CertificateFactory.getInstance("X.509");
    	  Slot[] slots = m_pkcs11Module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT); 
    	  int nNr = 0;
          for(int i = 0; (slots != null) && (i < slots.length); i++) {
            SlotInfo si = slots[i].getSlotInfo(); // get information about this slot object
            if(m_logger.isDebugEnabled())
            	m_logger.debug("Slot " + i + ": " + si);
            if(si.isTokenPresent()) { // indicates, if there is a token present in this slot
              Token tok = slots[i].getToken();
              if(m_logger.isDebugEnabled())
            	m_logger.debug("Token: " + tok);
              sess = tok.openSession(Token.SessionType.SERIAL_SESSION,
                      Token.SessionReadWriteBehavior.RO_SESSION,null,null);
              X509PublicKeyCertificate templCert = new X509PublicKeyCertificate();
              sess.findObjectsInit(templCert);
              iaik.pkcs.pkcs11.objects.Object[] certs = null;
              do {
            	  certs = sess.findObjects(1); // find next cert
            	  if(certs != null && certs.length > 0) {
            		  if(m_logger.isDebugEnabled())
            			  m_logger.debug("Certs: " + certs.length);
            		  for(int j = 0; (certs != null) && (j < certs.length); j++) {
            			  X509PublicKeyCertificate x509 = (X509PublicKeyCertificate)certs[j];
            			  byte[] derCert = x509.getValue().getByteArrayValue(); 
            			  X509Certificate cert = (X509Certificate)certFac.generateCertificate(new ByteArrayInputStream(derCert));
            			  TokenKeyInfo tki = new TokenKeyInfo(nNr, slots[i].getSlotID(), tok, x509.getId().getByteArrayValue(), x509.getLabel().toString(), cert);
            			  nNr++;
            			  if(m_logger.isDebugEnabled())
            				  m_logger.debug("Slot: " + i + " cert: " + j + " nr: " + tki.getCertSerial() + " CN: " + tki.getCertName() + " id: " + tki.getIdHex() + " signature: " + tki.isSignatureKey());
            			  vec.add(tki);
            		  }
            	  } // loop until all certs read
              } while(certs != null && certs.length > 0);
              sess.closeSession();
              sess = null;
            }
          }
    	} catch(Exception e) {
            m_pkcs11Module = null; // reset since we had an error
            DigiDocException.handleException(e, DigiDocException.ERR_CRYPTO_DRIVER);
        } finally {
        	try {
        		if(sess != null)
        			sess.closeSession();
        	} catch(Exception ex) {
        		m_logger.error("Error closing session: " + ex);
        	}
        }
    	TokenKeyInfo[] arr = new TokenKeyInfo[vec.size()];
    	for(int i = 0; i < vec.size(); i++)
    		arr[i] = (TokenKeyInfo)vec.elementAt(i);
    	return arr;
    }

    /**
     * Initializes Java cryptography provider
     */
    private void initProvider()
        throws DigiDocException
    {
        try {
            m_secProvider = (Provider)Class.forName(ConfigManager.
            instance().getProperty("DIGIDOC_SECURITY_PROVIDER")).newInstance();
            Security.addProvider(m_secProvider);
        } catch(Exception ex) {
            m_secProvider = null;
            DigiDocException.handleException(ex, DigiDocException.ERR_CRYPTO_PROVIDER);
        }
    }

    /**
     * Finds keys of specific type
     * @param bSign true if searching signature keys
     * @return array of key infos
     */
    public TokenKeyInfo[] getTokensOfType(boolean bSign)
    {
    	int nToks = 0;
    	boolean bKeyUsageCheck = ConfigManager.instance().getBooleanProperty("KEY_USAGE_CHECK", true);
    	for (int i = 0; (m_tokens != null) && (i < m_tokens.length); i++) {
            TokenKeyInfo tki = m_tokens[i]; 
            if(m_logger.isDebugEnabled())
                m_logger.debug("Token: " + i + " is-sign: " + tki.isSignatureKey() + " is-crypt: " + tki.isEncryptKey() + " nr: " + tki.getCertSerial() + " CN: " + tki.getCertName() + " id: " + tki.getIdHex());
            if((bSign && (tki.isSignatureKey() || !bKeyUsageCheck)) || (!bSign && tki.isEncryptKey()))
            	nToks++;
        }
    	TokenKeyInfo[] arr = new TokenKeyInfo[nToks];
    	for (int i = 0, j = 0; (m_tokens != null) && (i < m_tokens.length); i++) {
            TokenKeyInfo tki = m_tokens[i]; 
            if((bSign && (tki.isSignatureKey() || !bKeyUsageCheck)) || (!bSign && tki.isEncryptKey())) {
            	if(m_logger.isDebugEnabled())
                    m_logger.debug("Using token: " + i + " is-sign: " + tki.isSignatureKey() + " is-crypt: " + tki.isEncryptKey() + " nr: " + tki.getCertSerial() + " CN: " + tki.getCertName() + " id: " + tki.getIdHex());
               	arr[j++] = tki;
            }
        }
    	return arr;
    }
    
    /**
     * Finds token with slot id and certificate label
     * @param nSlotId slot id
     * @param label cert label
     * @return found token or null
     */
    public TokenKeyInfo getTokenWithSlotIdAndLabel(long nSlotId, String label)
    {
    	for (int i = 0; (m_tokens != null) && (i < m_tokens.length); i++) {
            TokenKeyInfo tki = m_tokens[i]; 
            if(tki.getSlot() == nSlotId && tki.getLabel().equals(label))
            	return tki;
        }
    	return null;
    }
    
    /**
     * Finds certificate slot id and certificate label
     * @param nSlotId slot id
     * @param label cert label
     * @return found certificate or null
     */
    public X509Certificate getCertificateWithSlotIdAndLabel(long nSlotId, String label)
    {
    	TokenKeyInfo tki = getTokenWithSlotIdAndLabel(nSlotId, label);
        if(tki != null)
        	return tki.getCert();
    	return null;
    }
    
    
    /**
     * Returns a list of all available key names (cert CN)
     * @return an array of all available key names (cert CN)
     * @throws DigiDocException if reading the token information fails.
     */
    public String[] getAvailableTokenNames()
        throws DigiDocException 
    { 
        if(m_pkcs11Module == null)
            initPKCS11();
        String[] names = new String[m_tokens.length];
        for (int i = 0; (m_tokens != null) && (i < m_tokens.length); i++) {
          TokenKeyInfo tki = m_tokens[i]; // get information about this token
          names[i] = tki.getCertName(); // get the label of this token
        } 
        return names;
    } 
    
    /**
     * Method opens a new session to perfom operations on 
     * specified token and logs in the user
     * or the security officer to the session.
     * @param bSignSession true if we want to open a session with signature token
     * @param token tokens order number
     * @param pin the PIN.
     * @throws DigiDocException if the session could not be opened or if login fails.
     */
    public void openSession(TokenKeyInfo tki, String pin)
        throws DigiDocException
    { 
        if(m_pkcs11Module == null)
            initPKCS11();
        try {
        	// close the old session if necessary
            if(m_currentSession != null)
                 closeSession();
            if(m_logger.isDebugEnabled())
       				m_logger.debug("Open session for token: " + tki);
       		if(m_logger.isDebugEnabled())
           			m_logger.debug("Open session for: " + 
           					((tki != null) ? tki.getCertName() + " id: " + tki.getIdHex() + 
           				" sign: " + tki.isSignatureKey() + " crypt: " + tki.isEncryptKey() : "NULL"));
           	if(tki != null) {
           		// open a new session to perfom operations on this token
           		m_currentSession = tki.getToken().
           				openSession(Token.SessionType.SERIAL_SESSION,
           							Token.SessionReadWriteBehavior.RO_SESSION,null,null);
           		m_selToken = tki;
           	}
       		else
       			if(m_logger.isDebugEnabled())
           			m_logger.debug("No suitable token found!");
            // logs in the user or the security officer to the session
       		if(m_currentSession != null && m_selToken != null) {
       			if(m_logger.isDebugEnabled())
           			m_logger.debug("Login for: " + m_selToken.getCertName() + " id: " + m_selToken.getIdHex());
       			try {
       				m_currentSession.login(Session.UserType.USER, pin.toCharArray()); 
       			} catch(iaik.pkcs.pkcs11.wrapper.PKCS11Exception ex) {
       	            m_logger.error("Pkcs11 error: " + ex);
       	            if(ex.getErrorCode() == PKCS11Constants.CKR_USER_ALREADY_LOGGED_IN) {
       	            	m_logger.error("User already logged in ok");
       	            } else
       	            	DigiDocException.handleException(ex, DigiDocException.ERR_TOKEN_LOGIN);
       	           }
       		}
        } catch(TokenException e) {
            m_selToken = null;
			m_currentSession = null;
            DigiDocException.handleException(e, DigiDocException.ERR_TOKEN_LOGIN);
        } 
    } 
    
    /**
     * Method opens a new session to perfom operations on 
     * specified token and logs in the user
     * or the security officer to the session.
     * @param bSignSession true if we want to open a session with signature token
     * @param token tokens order number
     * @param pin the PIN.
     * @throws DigiDocException if the session could not be opened or if login fails.
     */
    public void openSession(boolean bSignSession, int token, String pin)
        throws DigiDocException
    { 
        if(m_pkcs11Module == null)
            initPKCS11();
        try {
            // don't login if the session exists
            if(m_currentSession == null || m_selToken == null ||
            	(bSignSession && !m_selToken.isSignatureKey()) ||
            	(!bSignSession && m_selToken.isSignatureKey())) {
                // close the old session if necessary
                if(m_currentSession != null)
                     closeSession();
                if(m_logger.isDebugEnabled())
       				m_logger.debug("Open session for token: " + token);
       			TokenKeyInfo tki = null;
       			TokenKeyInfo[] tkis = getTokensOfType(bSignSession);
       			if(token >= 0 && tkis != null && token < tkis.length)
       				tki = tkis[token];
       			if(m_logger.isDebugEnabled())
           			m_logger.debug("Open " + (bSignSession ? "sign" : "auth") + " session for: " + 
           					((tki != null) ? tki.getCertName() + " id: " + tki.getIdHex() + 
           				" sign: " + tki.isSignatureKey() + " crypt: " + tki.isEncryptKey() : "NULL"));
           		if(tki != null) {
           			// open a new session to perfom operations on this token
           			m_currentSession = tki.getToken().
           				openSession(Token.SessionType.SERIAL_SESSION,
           							Token.SessionReadWriteBehavior.RO_SESSION,null,null);
           			m_selToken = tki;
           		}
       			else
       				if(m_logger.isDebugEnabled())
           				m_logger.debug("No suitable token found!");
                // logs in the user or the security officer to the session
       			if(m_currentSession != null && m_selToken != null) {
       				if(m_logger.isDebugEnabled())
           				m_logger.debug("Login for: " + m_selToken.getCertName() + " id: " + m_selToken.getIdHex() /*+ " PIN: \'" + pin + "\'"*/);
       				try {
       					m_currentSession.login(Session.UserType.USER, pin.toCharArray()); 
       				} catch(iaik.pkcs.pkcs11.wrapper.PKCS11Exception ex) {
       	            	m_logger.error("Pkcs11 error: " + ex);
       	            	if(ex.getErrorCode() == PKCS11Constants.CKR_USER_ALREADY_LOGGED_IN) {
       	            		m_logger.error("User already logged in ok");
       	            	} else
       	            		DigiDocException.handleException(ex, DigiDocException.ERR_TOKEN_LOGIN);
       	            }
       			}
            }
        } catch(TokenException e) {
            m_selToken = null;
			m_currentSession = null;
            DigiDocException.handleException(e, DigiDocException.ERR_TOKEN_LOGIN);
        } 
    } 
    byte[] tsign = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
    		0x10, 0x11, 0x12, 0x13    };
    
    /**
     * Method returns a digital signature. It finds the RSA private 
     * key object from the active token and
     * then signs the given data with this key and RSA mechanism.
     * @param digest digest of the data to be signed.
     * @param token token index
     * @param pin users pin code
     * @param sig Signature object to provide info about desired signature method
     * @return an array of bytes containing digital signature.
     * @throws DigiDocException if signing the data fails.
     */
    public byte[] sign(byte[] digest, int token, String pin, Signature sig) 
        throws DigiDocException 
    {
        byte[] sigVal = null;
        if(m_currentSession == null)
            openSession(true, token, pin);
        try {
        	if(m_logger.isDebugEnabled())
       			m_logger.debug("Sign with token: " + token + " key: " + 
       					((m_selToken != null) ? m_selToken.getCertName() : "NULL") + " id: " + 
       					((m_selToken != null) ? m_selToken.getIdHex() : "NULL") + 
       					" dig-len: " + ((digest != null) ? digest.length : 0) + " dig: " + 
       					((digest != null) ? Base64Util.encode(digest) : "NULL"));
            // the RSA private key object that serves as a template for searching
            RSAPrivateKey tempKey = new RSAPrivateKey(); 
            // initializes a find operations to find RSA private key objects
            m_currentSession.findObjectsInit(tempKey); 
            // find first
            iaik.pkcs.pkcs11.objects.Object[] keys = null;
                
            RSAPrivateKey sigKey = null;
            boolean bFound = false;
            do {
            	keys = m_currentSession.findObjects(1); 
            	if(keys != null && keys.length > 0) {
            		for(int i = 0; !bFound && i < keys.length; i++) {
            			sigKey = (RSAPrivateKey)keys[i];
            			String keyIdHex = SignedDoc.bin2hex(sigKey.getId().getByteArrayValue());
            			if(m_logger.isDebugEnabled())
            				m_logger.debug("Key " + i + " id: " + keyIdHex);
            			if(keyIdHex != null && m_selToken.getIdHex() != null && keyIdHex.equals(m_selToken.getIdHex())) {
            				if(m_logger.isDebugEnabled())
            					m_logger.debug("Using key " + i + " id: " + keyIdHex);
            				Mechanism sigMech = Mechanism.RSA_PKCS;
            				// initializes a new signing operation
            				m_currentSession.signInit(sigMech, sigKey); 
            				byte[] ddata = ConvertUtils.addDigestAsn1Prefix(digest);
            				sigVal = m_currentSession.sign(ddata); // signs the given data with the key and mechanism given to the signInit method
            				if(m_logger.isDebugEnabled())
            					m_logger.debug("Signature len: " + ((sigVal != null) ? sigVal.length : 0));
            				break;
            			}
            		} // for
            	} // if keys found
            } while(!bFound && keys != null && keys.length > 0);
            m_currentSession.findObjectsFinal(); // finalizes a find operation
            // close session
            closeSession();
        } catch(TokenException e) {
            DigiDocException.handleException(e, DigiDocException.ERR_SIGN);
        } 
        return sigVal;
    } 
    
    
    /**
     * Method returns a digital signature. It finds the RSA private 
     * key object from the active token and
     * then signs the given data with this key and RSA mechanism.
     * @param digest digest of the data to be signed.
     * @param nSlotId slot id
     * @param certLabel cert label
     * @param pin users pin code
     * @param sig Signature object to provide info about desired signature method
     * @return an array of bytes containing digital signature.
     * @throws DigiDocException if signing the data fails.
     */
    public byte[] sign(byte[] digest, long nSlotId, String certLabel, String pin, Signature sig) 
        throws DigiDocException 
    {
        byte[] sigVal = null;
        TokenKeyInfo tki = getTokenWithSlotIdAndLabel(nSlotId, certLabel);
        if(tki == null) {
        	m_logger.error("No token with slot: " + nSlotId + " and label: " + certLabel + " found!");
        	return null;
        }
        if(m_currentSession == null)
            openSession(tki, pin);
        try {
        	if(m_logger.isDebugEnabled())
       			m_logger.debug("Sign with token: " + tki + " key: " + 
       					((m_selToken != null) ? m_selToken.getCertName() : "NULL") + " id: " + 
       					((m_selToken != null) ? m_selToken.getIdHex() : "NULL") + 
       					" dig-len: " + ((digest != null) ? digest.length : 0) + " dig: " + 
       					((digest != null) ? Base64Util.encode(digest) : "NULL"));
            // the RSA private key object that serves as a template for searching
            RSAPrivateKey tempKey = new RSAPrivateKey(); 
            // initializes a find operations to find RSA private key objects
            m_currentSession.findObjectsInit(tempKey); 
            // find first
            iaik.pkcs.pkcs11.objects.Object[] foundKeys = null;
            boolean bFound = false;
    		do {
            	foundKeys = m_currentSession.findObjects(1);
            	if(foundKeys != null && foundKeys.length > 0) { 
            		RSAPrivateKey sigKey = null;
            		if(m_logger.isDebugEnabled())
            			m_logger.debug("Keys: " + foundKeys.length);
            		for(int i = 0; !bFound && (i < foundKeys.length); i++) {
            			sigKey = (RSAPrivateKey)foundKeys[i];
            			String keyLabel = null;
            			if(sigKey.getLabel() != null) {
            				keyLabel = sigKey.getLabel().toString();
            				if(m_logger.isDebugEnabled())
            					m_logger.debug("Key " + i + " label: " + keyLabel);
            			}
            			if(keyLabel != null && m_selToken.getLabel() != null && keyLabel.equals(m_selToken.getLabel())) {
            				if(m_logger.isDebugEnabled())
            					m_logger.debug("Using key " + i + " label: " + keyLabel);
            				bFound = true;
            				Mechanism sigMech = Mechanism.RSA_PKCS;
            				// initializes a new signing operation
            				m_currentSession.signInit(sigMech, sigKey); 
            				byte[] ddata = ConvertUtils.addDigestAsn1Prefix(digest);
            				sigVal = m_currentSession.sign(ddata); // signs the given data with the key and mechanism given to the signInit method
            				if(m_logger.isDebugEnabled())
            					m_logger.debug("Signature len: " + ((sigVal != null) ? sigVal.length : 0));
            				break;
            			}
            		} 
            	} // if keys found
            } while(!bFound && foundKeys != null && foundKeys.length > 0);
    		if(!bFound)
            	m_logger.error("Failed to sign, token with slot: " + nSlotId + " and label: " + certLabel + " not found!");
            m_currentSession.findObjectsFinal(); // finalizes a find operation
            // close session
            closeSession();
        } catch(TokenException e) {
            DigiDocException.handleException(e, DigiDocException.ERR_SIGN);
        } 
        return sigVal;
    } 
    

    /**
     * Method returns a X.509 certificate object readed 
     * from the active token and representing an
     * user public key certificate value.
     * @return X.509 certificate object.
     * @throws DigiDocException if getting X.509 public key certificate 
     * fails or the requested certificate type X.509 is not available in 
     * the default provider package
     */
    public X509Certificate getCertificate(int token, String pin)
        throws DigiDocException 
    {
    	if(m_logger.isDebugEnabled())
       		m_logger.debug("Get cert in slot: " + token);
        if(m_currentSession == null)
            openSession(true, token, pin);
        if(m_logger.isDebugEnabled())
       		m_logger.debug("Got cert in slot: " + token + " nr: " + m_selToken.getNr() + " sign: " + m_selToken.isSignatureKey() + " enc: " + m_selToken.isEncryptKey());
        if(m_selToken != null)
           	return m_selToken.getCert();
        return null;
    } 
    
    /**
     * Method returns a X.509 certificate object readed 
     * from the active token and representing an
     * user public key certificate value.
     * @return X.509 certificate object.
     * @throws DigiDocException if getting X.509 public key certificate 
     * fails or the requested certificate type X.509 is not available in 
     * the default provider package
     */
    public X509Certificate getAuthCertificate(int token, String pin)
        throws DigiDocException 
    {
        if(m_currentSession == null)
            openSession(false, token, pin);
        if(m_logger.isDebugEnabled())
       		m_logger.debug("Get cert for token: " + token);
        if(m_selToken != null)
           	return m_selToken.getCert();
        return null;
    }
    
	/**
	* Method decrypts the data with the RSA private key
	* corresponding to this certificate (which was used
	* to encrypt it). Decryption will be done on the card.
	* This operation closes the possibly opened previous
	* session with signature token and opens a new one with
	* authentication tokne if necessary
	* @param data data to be decrypted.
	* @param token index of authentication token
	* @param pin PIN code
	* @return decrypted data.
	* @throws DigiDocException for all decryption errors
	*/
	public byte[] decrypt(byte[] data, int token, String pin) 
			throws DigiDocException 
	{
			byte[] value = null;
			if(m_currentSession == null) {
				openSession(false, token, pin);
			}
			try {
				if(m_logger.isDebugEnabled()) {
					m_logger.debug("Decrypting " + data.length + " bytes");
					m_logger.debug("Decrypting with token: " + m_selToken.getNr());
					m_logger.debug("session: " + m_currentSession);
				}
				RSAPrivateKey authKey = new RSAPrivateKey(); // the RSA private key object that serves as a template for searching
				m_currentSession.findObjectsInit(authKey); // initializes a find operations to find RSA private key objects
				iaik.pkcs.pkcs11.objects.Object[] keys = null;
				boolean bFound = false;
        		do {
	            	keys = m_currentSession.findObjects(1);
	            	if(keys != null && keys.length > 0) {
	            		RSAPrivateKey key = null;
	            		for(int i = 0; !bFound && (i < keys.length); i++) {
	            			key = (RSAPrivateKey)keys[i];
	            			String keyIdHex = null;
	    	                if(key.getId() != null) {
	    	                	keyIdHex = SignedDoc.bin2hex(key.getId().getByteArrayValue());
	    	                	if(m_logger.isDebugEnabled())
	    	                		m_logger.debug("Key " + i + " id: " + keyIdHex);
	    	                }
	    	                if(keyIdHex != null && m_selToken.getIdHex() != null && keyIdHex.equals(m_selToken.getIdHex())) {
	    	                	bFound = true;
	    	                	if(m_logger.isDebugEnabled())
	    	               			m_logger.debug("Using key " + i + " id: " + keyIdHex);
	            				Mechanism m = Mechanism.RSA_PKCS;
	            				m_currentSession.decryptInit(m, key); // initializes a new signing operation
	            				if(m_logger.isDebugEnabled()) 
	            					m_logger.debug("decryptInit OK");
	            				value = m_currentSession.decrypt(data);
	            				if(m_logger.isDebugEnabled())
	            					m_logger.debug("value = " + value);
	            				break;
	            			} // end if
	            		}
	            	} // if keys found
				} while(!bFound && keys != null && keys.length > 0);
			if(m_logger.isInfoEnabled()) 
				m_logger.info("Decrypted " + ((data != null) ? data.length : 0) + " bytes, got: " + value.length);
			m_currentSession.findObjectsFinal(); // finalizes a find operation
			// close session
			closeSession();
		} catch (TokenException e) {
			DigiDocException.handleException(e, DigiDocException.ERR_XMLENC_DECRYPT);
		} // end catch
		return value;
	}

	/**
	* Method decrypts the data with the RSA private key
	* corresponding to this certificate (which was used
	* to encrypt it). Decryption will be done on the card.
	* This operation closes the possibly opened previous
	* session with signature token and opens a new one with
	* authentication tokne if necessary
	* @param data data to be decrypted.
	* @param slot slot id
	* @param label token label
	* @param pin PIN code
	* @return decrypted data.
	* @throws DigiDocException for all decryption errors
	*/
	public byte[] decrypt(byte[] data, long slot, String label, String pin) 
			throws DigiDocException 
	{
			byte[] value = null;
			TokenKeyInfo tki = getTokenWithSlotIdAndLabel(slot, label);
	        if(tki == null) {
	        	m_logger.error("No token with slot: " + slot + " and label: " + label + " found!");
	        	return null;
	        }
	        if(m_currentSession == null)
	            openSession(tki, pin);
			try {
				RSAPrivateKey authKey = new RSAPrivateKey(); // the RSA private key object that serves as a template for searching
				m_currentSession.findObjectsInit(authKey); // initializes a find operations to find RSA private key objects
				if(m_logger.isDebugEnabled()) {
					m_logger.debug("Decrypting " + data.length + " bytes");
					m_logger.debug("Decrypting with token: " + m_selToken.getNr());
					m_logger.debug("session: " + m_currentSession);
				}
				RSAPrivateKey key = null;
				boolean bFound = false;
				iaik.pkcs.pkcs11.objects.Object[] keys = null;
				do {
	            	keys = m_currentSession.findObjects(1);
	            	if(keys != null && keys.length > 0) {
	            		for(int i = 0; !bFound && (i < keys.length); i++) {
	            			key = (RSAPrivateKey)keys[i];
	            			String keyLabel = null;
	            			if(key.getLabel() != null) {
	            				keyLabel = key.getLabel().toString();
	            				if(m_logger.isDebugEnabled())
	            					m_logger.debug("Key " + i + " label: " + keyLabel);
	            			}
	            			if(keyLabel != null && m_selToken.getLabel() != null && keyLabel.equals(m_selToken.getLabel())) {
	            				if(m_logger.isDebugEnabled())
	            					m_logger.debug("Using key " + i + " label: " + keyLabel);
	            				bFound = true;
	            				Mechanism m = Mechanism.RSA_PKCS;
	            				m_currentSession.decryptInit(m, key); // initializes a new signing operation
	            				if(m_logger.isDebugEnabled()) 
	            					m_logger.debug("decryptInit OK");
	                			value = m_currentSession.decrypt(data);
	            				if(m_logger.isDebugEnabled())
	            					m_logger.debug("value = " + value);
	            				break;
	            			} // end if
	            		} // for
	            	} // if keys
				} while(!bFound && keys != null && keys.length > 0);
				if(!bFound)
	            	m_logger.error("Failed to sign, token with slot: " + slot + " and label: " + label + " not found!");
			if(m_logger.isInfoEnabled()) 
				m_logger.info("Decrypted " + ((data != null) ? data.length : 0) + " bytes, got: " + value.length);
			m_currentSession.findObjectsFinal(); // finalizes a find operation
			// close session
			closeSession();
		} catch (TokenException e) {
			DigiDocException.handleException(e, DigiDocException.ERR_XMLENC_DECRYPT);
		} // end catch
		return value;
	}

    /**
     * Method closes the current session.
     * @throws DigiDocException if closing the session fails.
     */
    public void closeSession() 
        throws DigiDocException 
    { 
        try {
        	if(m_logger.isDebugEnabled())
       			m_logger.debug("Closing card session");
            // closes this session
        	if(m_currentSession != null)
        		m_currentSession.closeSession(); 
            m_currentSession = null; // ???
        } catch(TokenException e) {
            DigiDocException.handleException(e, DigiDocException.ERR_TOKEN_LOGOUT);
        } 
    } 
    
    /**
     * This finalize method tries to finalize the module 
     * by calling finalize() of the PKCS#11 module.
     * @throws DigiDocException if PKCS#11 module finalization fails.
     */
    public void finalize()
        throws DigiDocException 
    {
        try {
            if(m_pkcs11Module != null)
                m_pkcs11Module.finalize(null); // finalizes this module
            m_isInitialized = false;
            m_pkcs11Module = null;
        } catch(TokenException e) {
            DigiDocException.handleException(e, DigiDocException.ERR_CRYPTO_FINALIZE);
        } 
    }
    
    /**
     * Resets the previous session
     * and other selected values
     */
    public void reset() 
        throws DigiDocException 
    {
    	if(m_logger.isDebugEnabled())
       			m_logger.debug("Resetting PKCS11SignatureFactory");
        m_selToken = null;
        closeSession();
        m_isInitialized = false;
        m_pkcs11Module = null; //???
        m_secProvider = null; //???
        finalize();
    }

    /**
	 * Returns signature factory type identifier
	 * @return factory type identifier
	 */
	public String getType()
	{
		return SIGFAC_TYPE_PKCS11;
	}
}
