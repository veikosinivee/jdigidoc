package ee.sk.digidoc.factory;
import ee.sk.digidoc.Base64Util;
import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.Signature;
import ee.sk.digidoc.SignedDoc;
import ee.sk.digidoc.TokenKeyInfo;
import ee.sk.utils.ConfigManager;
import ee.sk.utils.ConvertUtils;

import java.security.cert.X509Certificate;
import java.security.*;
import java.io.*;
import java.util.*;

import javax.crypto.Cipher;

import org.apache.log4j.Logger;

/**
 * PKCS#12 based signature implementation
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class Pkcs12SignatureFactory 
	implements SignatureFactory
{
	private KeyStore m_keyStore;
	/** log4j logger */
    private static Logger m_logger = Logger.getLogger(Pkcs12SignatureFactory.class);
    /** security provider */
    private Provider m_secProvider;
    
	/** 
     * initializes the implementation class 
     */
    public void init()
        throws DigiDocException
    {
    	initProvider();
    	if(m_keyStore == null) {
    		ConfigManager cfg = ConfigManager.instance();
    		String storeFile = cfg.getProperty("DIGIDOC_KEYSTORE_FILE");
    		String storeType = cfg.getProperty("DIGIDOC_KEYSTORE_TYPE");
    		String storePasswd = cfg.getProperty("DIGIDOC_KEYSTORE_PASSWD");
    		if(storeFile != null && storeType != null && storePasswd != null)
    			load(storeFile, storeType, storePasswd);
    	}
    }
    
    public boolean load(String storeName, String storeType, String passwd)
    throws DigiDocException
    {
    	try {
    		if(m_logger.isDebugEnabled())
    			m_logger.debug("Load store: " + storeName + " type: " + storeType);
    		m_keyStore = KeyStore.getInstance(storeType);
    		if(m_keyStore != null) {
    			m_keyStore.load(new FileInputStream(storeName), passwd.toCharArray());
    			return true;
    		}
    	} catch(Exception ex) {
    		m_logger.error("Error loading store: " + storeName + " - " + ex);
    	}
    	return false;
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
     * Reads all useable token keys
     * @return list of available token/key info
     * @throws DigiDocException
     */
    public TokenKeyInfo[] getTokenKeys()
    	throws DigiDocException
    {
    	return null;
    }
    
    /**
     * Finds keys of specific type
     * @param bSign true if searching signature keys
     * @return array of key infos
     */
    public TokenKeyInfo[] getTokensOfType(boolean bSign)
    {
    	return null;
    }
    
    /**
     * Method returns an array of strings representing the 
     * list of available token names.
     * @return an array of available token names.
     * @throws DigiDocException if reading the token information fails.
     */
    public String[] getAvailableTokenNames()
        throws DigiDocException
    {
    	Vector vec = new Vector();
    	try {
    		if(m_keyStore != null) {
    			Enumeration eAliases = m_keyStore.aliases();
    			while(eAliases.hasMoreElements()) {
    				String alias = (String)eAliases.nextElement();
    				vec.add(alias);
    			}
    		}
    	} catch(Exception ex) {
    		m_logger.error("Error reading store aliases: " + ex);
    	}
    	String[] arr = new String[vec.size()];
    	for(int i = 0; (vec != null) && (i < vec.size()); i++)
    		arr[i] = (String)vec.elementAt(i);
    	return arr;
    }
    
    /**
     * Returns the n-th token name or alias
     * @param nIdx index of token
     * @return alias
     */
    private String getTokenName(int nIdx)
    {
    	try {
    		if(m_keyStore != null) {
    			Enumeration eAliases = m_keyStore.aliases();
    			for(int i = 0; eAliases.hasMoreElements(); i++) {
    				String alias = (String)eAliases.nextElement();
    				if(i == nIdx)
    					return alias;
    			}
    		}
    	} catch(Exception ex) {
    		m_logger.error("Error reading store aliases: " + ex);
    	}
    	return null;
    }
    
    public static java.security.Signature sigMeth2SigSignatureInstance(Signature sig, Key key)
    		throws DigiDocException
    {
    	java.security.Signature instance = null;
    	String sigMeth = null, sigType = null;
    	try {
		  if(sig != null && sig.getSignedInfo() != null && sig.getSignedInfo().getSignatureMethod() != null) 
			sigMeth = sig.getSignedInfo().getSignatureMethod();
		  sigType = ConfigManager.instance().sigMeth2SigType(sigMeth);
		  if(m_logger.isDebugEnabled())
			m_logger.debug("Key: " + ((key != null) ? "OK, algorithm: " + key.getAlgorithm() : "NULL") + " method: " + sigMeth + " type: " + sigType);
		  if(sigType == null)
			throw new DigiDocException(DigiDocException.ERR_SIGNATURE_METHOD, "SignatureMethod not specified!", null);
		  instance = java.security.Signature.getInstance(sigType, ConfigManager.addProvider());			
    	} catch(Exception ex) {
    		m_logger.error("Error constructing signature instance: " + ex);
    	}
    	return instance;
    }
    
    /**
     * Method returns a digital signature. It finds the RSA private 
     * key object from the active token and
     * then signs the given data with this key and RSA mechanism.
     * @param digest digest of the data to be signed.
     * @param token token index
     * @param passwd users pin code or in case of pkcs12 file password
     * @param sig Signature object to provide info about desired signature method
     * @return an array of bytes containing digital signature.
     * @throws DigiDocException if signing the data fails.
     */
    public byte[] sign(byte[] xml, int token, String passwd, Signature sig) 
        throws DigiDocException
    {
    	try {
    		if(m_keyStore == null)
    			throw new DigiDocException(DigiDocException.ERR_NOT_INITED, "Keystore not initialized", null);
    		String alias = getTokenName(token);
    		if(alias == null)
    			throw new DigiDocException(DigiDocException.ERR_TOKEN_LOGIN, "Invalid token nr: " + token, null);
    		// get key
    		if(m_logger.isDebugEnabled())
    			m_logger.debug("loading key: " + alias + " passwd-len: " + ((passwd != null) ? passwd.length() : 0));
    		Key key = m_keyStore.getKey(alias, passwd.toCharArray());
    		if(m_logger.isDebugEnabled())
    			m_logger.debug("Key: " + ((key != null) ? "OK, algorithm: " + key.getAlgorithm() : "NULL"));
    		if(key == null)
    			throw new DigiDocException(DigiDocException.ERR_TOKEN_LOGIN, "Invalid password for token nr: " + token, null);
    		String sigMeth = null;
    		if(sig != null && sig.getSignedInfo() != null && sig.getSignedInfo().getSignatureMethod() != null) 
    			sigMeth = sig.getSignedInfo().getSignatureMethod();
    		if(m_logger.isDebugEnabled())
    			m_logger.debug("Signing\n---\n" + new String(xml) + "\n---\n method: " + sigMeth);
    		java.security.Signature instance = sigMeth2SigSignatureInstance(sig, key);
    		if(m_logger.isDebugEnabled())
    			m_logger.debug("Signature instance: " + ((instance != null) ? "OK" : "NULL"));
    		instance.initSign((PrivateKey)key);
    		instance.update(xml);
    		byte[] signature = instance.sign();
    		if(m_logger.isDebugEnabled())
    			m_logger.debug("Signature len: " + ((signature != null) ? signature.length : 0) + "\n---\n sig: " + ConvertUtils.bin2hex(signature));
    		return signature;
    	} catch(DigiDocException ex) {
    		m_logger.error("DigiDoc Error signing: " + ex);
    		throw ex;
    	} catch(Exception ex) {
    		m_logger.error("Error signing: " + ex);
    	}
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
    public X509Certificate getCertificate(int token, String pin)
        throws DigiDocException
    {
    	if(m_keyStore == null)
			throw new DigiDocException(DigiDocException.ERR_NOT_INITED, "Keystore not initialized", null);
		String alias = getTokenName(token);
		if(alias == null)
			throw new DigiDocException(DigiDocException.ERR_TOKEN_LOGIN, "Invalid token nr: " + token, null);
		try {
			return (X509Certificate)m_keyStore.getCertificate(alias);
		} catch(Exception ex) {
    		m_logger.error("Error reading cert for alias: " + alias + " - " + ex);
    	}
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
        return getCertificate(token, pin);
    }
    
    /**
     * Resets the previous session
     * and other selected values
     */
    public void reset() 
        throws DigiDocException
    {
    	m_keyStore = null;
    }
       
    /**
     * Method closes the current session.
     * @throws DigiDocException if closing the session fails.
     */
    public void closeSession() 
        throws DigiDocException 
    {
    	reset();
    }
    
	/**
	 * Method decrypts the data with the RSA private key
	 * corresponding to this certificate (which was used
	 * to encrypt it). Decryption will be done with keystore
	 * @param data data to be decrypted.
	 * @param token index of authentication token
	 * @param pin PIN code
	 * @return decrypted data.
	 * @throws DigiDocException for all decryption errors
	 */
	public byte[] decrypt(byte[] data, int token, String pin) 
		throws DigiDocException
	{
		try {
    		if(m_keyStore == null)
    			throw new DigiDocException(DigiDocException.ERR_NOT_INITED, "Keystore not initialized", null);
    		String alias = getTokenName(token);
    		if(alias == null)
    			throw new DigiDocException(DigiDocException.ERR_TOKEN_LOGIN, "Invalid token nr: " + token, null);
    		// get key
    		if(m_logger.isDebugEnabled())
    			m_logger.debug("loading key: " + alias + " passwd-len: " + ((pin != null) ? pin.length() : 0));
    		Key key = m_keyStore.getKey(alias, pin.toCharArray());
    		if(m_logger.isDebugEnabled())
    			m_logger.debug("Key: " + ((key != null) ? "OK, algorithm: " + key.getAlgorithm() : "NULL"));
    		if(key == null)
    			throw new DigiDocException(DigiDocException.ERR_TOKEN_LOGIN, "Invalid password for token: " + alias, null);
    		Cipher cipher = Cipher.getInstance("RSA");
    		cipher.init(Cipher.DECRYPT_MODE, key);
    		byte[] decdata = cipher.doFinal(data);
    		if(m_logger.isDebugEnabled())
    			m_logger.debug("Decrypted len: " + ((decdata != null) ? decdata.length : 0));
    		return decdata;
    	} catch(Exception ex) {
    		m_logger.error("Error decrypting: " + ex);
    	}
    	return null;
	}
	
	/**
	 * Returns signature factory type identifier
	 * @return factory type identifier
	 */
	public String getType()
	{
		return SIGFAC_TYPE_PKCS12;
	}
}
