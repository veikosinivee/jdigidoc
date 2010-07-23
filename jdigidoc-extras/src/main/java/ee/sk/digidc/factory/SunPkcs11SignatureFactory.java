package ee.sk.digidoc.factory;
import ee.sk.digidoc.Base64Util;
import ee.sk.digidoc.CertValue;
import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.Signature;
import ee.sk.digidoc.SignedDoc;
import java.util.*;
import java.security.*; 
import java.security.KeyStore.ProtectionParameter;
import java.security.cert.*; 
import iaik.pkcs.pkcs11.*; 
import iaik.pkcs.pkcs11.objects.*; 
import ee.sk.utils.ConfigManager;
import ee.sk.utils.ConvertUtils;

import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.util.Vector;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import org.apache.log4j.Logger;
import ee.sk.digidoc.TokenKeyInfo;

/**
 * PKCS#11 based signature implementation using
 * Sun pkcs11 API. This module was created in order to test
 * the signature method used by DSS -
 * https://joinup.ec.europa.eu/svn/sd-dss/trunk/apps/dss/
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class SunPkcs11SignatureFactory implements SignatureFactory 
{
	/** log4j logger */
    private static Logger m_logger = Logger.getLogger(SunPkcs11SignatureFactory.class);
    private Provider m_provider;
    private KeyStore m_keyStore;
    public String m_alias = null;
    
    
    /** 
     * initializes the implementation class 
     */
    public void init()
        throws DigiDocException
    {
    	//DIGIDOC_SIGN_PKCS11_DRIVER
    	m_provider = null;
    	m_keyStore = null;
    }
    
    /** 
     * initializes the implementation class 
     */
    public boolean init(String driver, String passwd, int nSlot)
        throws DigiDocException
    {
    	//DIGIDOC_SIGN_PKCS11_DRIVER
    	m_provider = null;
    	m_keyStore = null;
    	boolean bOk = initProvider(driver, passwd, nSlot);
    	if(bOk)
    		bOk = initKeystore(passwd);
    	return bOk;
    }
    
    private boolean initProvider(String driver, String passwd, int nSlot)
    		throws DigiDocException
    {
    	try {
    		String config = "name=OpenSC\n" + "library=" + driver + "\n" +
    				"slotListIndex=" + nSlot; // + "disabledMechanisms = { CKM_SHA1_RSA_PKCS }\n";
    		if(m_logger.isDebugEnabled())
    			m_logger.debug("init driver with config:\n---\n" + config + "\n---\n");
            byte[] bcfg = config.getBytes();
            ByteArrayInputStream confStream = new ByteArrayInputStream(bcfg);
            sun.security.pkcs11.SunPKCS11 pkcs11 = new sun.security.pkcs11.SunPKCS11(confStream);
            m_provider = (Provider)pkcs11;
            Security.addProvider(m_provider);
            if(m_logger.isDebugEnabled())
    			m_logger.debug("Driver inited");
    		return true;
    	} catch(Exception ex) {
    		m_logger.error("Error init provider: " + ex);
    	}
    	return false;
    }
    
    private boolean initKeystore(String passwd)
    		throws DigiDocException
    {
    	try {
    		String javaLibPath = System.getProperty("java.library.path");
            if(m_logger.isDebugEnabled())
    			m_logger.debug("init keystore" + " in: " + javaLibPath + " provider: " + ((m_provider != null) ? "OK" : "NULL"));
    		if(m_provider == null)
    			throw new DigiDocException(DigiDocException.ERR_INIT_SIG_FAC, "Provider not initialized!", null);
    		// load keystore
    		m_keyStore = KeyStore.getInstance("PKCS11", m_provider);
    		if(m_logger.isDebugEnabled())
    			m_logger.debug("Load keystore: " + m_provider.getName() + " - " + m_provider.getInfo());
    		m_keyStore.load(null, passwd.toCharArray());
    		// list keystore
    		Enumeration eAliases = m_keyStore.aliases();
			while(eAliases.hasMoreElements()) {
				String al = (String)eAliases.nextElement();
				if(m_logger.isDebugEnabled())
	    			m_logger.debug("Alias: " + al);
				if(m_alias == null)
					m_alias = al;
			}
    		/*final String p = passwd;
    		m_keyStore.load(new KeyStore.LoadStoreParameter() {
    			public ProtectionParameter getProtectionParameter() {
    				try {
    	                return new KeyStore.CallbackHandlerProtection(new CallbackHandler() {
                		public void handle(Callback[] callbacks) throws IOException,
                                UnsupportedCallbackException {
                            for (int i = 0; i < callbacks.length; i++) {
                            	Callback c = callbacks[i];
                                if (c instanceof PasswordCallback) {
                                    ((PasswordCallback) c).setPassword(p.toCharArray());
                                    return;
                                }
                            }
                            throw new RuntimeException("No password callback");
                        }
                    });
    				} catch (Exception e) {
    	                if (e instanceof sun.security.pkcs11.wrapper.PKCS11Exception) {
    	                    if ("CKR_PIN_INCORRECT".equals(e.getMessage())) {
    	                    	throw new RuntimeException("Invalid PIN");
    	                        //throw new DigiDocException(DigiDocException.ERR_TOKEN_LOGIN, "Invalid PIN", e);
    	                    }
    	                }
    				}
    				return null;
                }
            });*/
    		if(m_logger.isDebugEnabled())
    			m_logger.debug("Keystore loaded");
    		return true;
    	} catch(Exception ex) {
    		if (ex instanceof sun.security.pkcs11.wrapper.PKCS11Exception) {
                if ("CKR_PIN_INCORRECT".equals(ex.getMessage())) {
                	DigiDocException.handleException(ex, DigiDocException.ERR_TOKEN_LOGIN);
                    //throw new DigiDocException(DigiDocException.ERR_TOKEN_LOGIN, "Invalid PIN", e);
                }
            }
    		m_logger.error("Error init keystore: " + ex);
    	}
    	return false;
    }
    
    /**
     * Reads all useable token keys
     * @return list of available token/key info
     * @throws DigiDocException
     */
    public TokenKeyInfo[] getTokenKeys()
    	throws DigiDocException
    {
    	TokenKeyInfo[] keys = null;
    	try {
    		Enumeration eAliases = m_keyStore.aliases();
    		Vector vec = new Vector();
    		while(eAliases.hasMoreElements()) {
    			String sAlias = (String)eAliases.nextElement();
    			X509Certificate cert = (X509Certificate)m_keyStore.getCertificate(sAlias);
    			TokenKeyInfo tok = new TokenKeyInfo(0, 0, null, sAlias.getBytes(), ConvertUtils.getCommonName(cert.getSubjectDN().getName()), cert);
    			vec.add(tok);
    		}
    		keys = new TokenKeyInfo[vec.size()];
    		for(int i = 0; i < vec.size(); i++) 
    			keys[i] = (TokenKeyInfo)vec.elementAt(i);
    		
    	} catch(Exception ex) {
    		m_logger.error("Error init provider: " + ex);
    	}
    	return keys;
    }
    
    /**
     * Finds keys of specific type
     * @param bSign true if searching signature keys
     * @return array of key infos
     */
    public TokenKeyInfo[] getTokensOfType(boolean bSign)
    {
    	try {
    	if(m_keyStore != null) {
    		X509Certificate cert = (X509Certificate)m_keyStore.getCertificate(m_alias);
			TokenKeyInfo tok = new TokenKeyInfo(0, 0, null, m_alias.getBytes(), ConvertUtils.getCommonName(cert.getSubjectDN().getName()), cert);
			TokenKeyInfo[] at = new TokenKeyInfo[1];
			at[0] = tok;
			return at;
    	}
    	} catch(Exception ex) {
    		m_logger.error("Error init provider: " + ex);
    	}
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
    	String [] as = new String[1];
    	as[0] = m_alias;
    	return as;
    }
    
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
    	try {
    		ConfigManager cfg = ConfigManager.instance();
    		if(m_provider == null)
    			initProvider(cfg.getProperty("DIGIDOC_SIGN_PKCS11_DRIVER"), pin, token);
    		if(m_keyStore == null)
    			initKeystore(pin);
    		if(m_keyStore == null) {
    			m_logger.error("Failed to load keystore");
    			throw new DigiDocException(DigiDocException.ERR_TOKEN_LOGIN, "Keystore load failed", null);
    		}
    			
    		try {
    			if(m_logger.isDebugEnabled() && digest != null)
	    			m_logger.debug("Signing: " + ConvertUtils.bin2hex(digest) + " len: " + digest.length + " with: " + m_alias + " on: " + m_provider.getName());
    			byte[] ddata = ConvertUtils.addDigestAsn1Prefix(digest);
            	Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.ENCRYPT_MODE, m_keyStore.getKey(m_alias, pin.toCharArray()));
                byte[] sdata = null;
                if(ddata != null)
                  sdata = cipher.doFinal(ddata);
                if(m_logger.isDebugEnabled())
	    			m_logger.debug("Signature: " + ConvertUtils.bin2hex(sdata) + " len: " + ((sdata != null) ? sdata.length : 0));
                return sdata;
            } catch (NoSuchPaddingException e) {
                throw new RuntimeException(e);
            } catch (InvalidKeyException e) {
                throw new RuntimeException(e);
            } catch (IllegalBlockSizeException e) {
                throw new RuntimeException(e);
            } catch (BadPaddingException e) {
                // More likely bad password
            	throw new DigiDocException(DigiDocException.ERR_TOKEN_LOGIN, "Invalid PIN", e);
            }
    	} catch(Exception ex) {
    		m_logger.error("Error init provider: " + ex);
    		ex.printStackTrace();
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
    	try {
    		ConfigManager cfg = ConfigManager.instance();
    		if(m_provider == null)
    			initProvider(cfg.getProperty("DIGIDOC_SIGN_PKCS11_DRIVER"), pin, token);
    		if(m_keyStore == null)
    			initKeystore(pin);
    		if(m_keyStore == null) {
    			m_logger.error("Failed to load keystore");
    			throw new DigiDocException(DigiDocException.ERR_TOKEN_LOGIN, "Keystore load failed", null);
    		}
    		if(m_logger.isDebugEnabled())
    			m_logger.debug("Get cert for: " + m_alias + " on: " + m_provider.getName());
			X509Certificate cert = (X509Certificate)m_keyStore.getCertificate(m_alias);
    		return cert;
    	} catch(Exception ex) {
    		m_logger.error("Error init provider: " + ex);
    		ex.printStackTrace();
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
    	X509Certificate cert = null;
    	cert = getCertificate(token, pin);
    	//if(ConvertUtils.is
    	return cert;
    }
    
    /**
     * Method closes the current session.
     * @throws DigiDocException if closing the session fails.
     */
    public void closeSession() 
        throws DigiDocException 
    {
    	try {
    		m_provider = null;
            m_keyStore = null;
            m_alias = null;
    	} catch(Exception ex) {
    		m_logger.error("Error resetting pkcs11 factory: " + ex);
    	}
    }
    
    /**
     * Resets the previous session
     * and other selected values
     */
    public void reset() 
        throws DigiDocException
    {
    	try {
    		if (m_provider != null) {
                try {
                    Security.removeProvider(m_provider.getName());
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
    		m_provider = null;
            m_keyStore = null;
            m_alias = null;
    	} catch(Exception ex) {
    		m_logger.error("Error resetting pkcs11 factory: " + ex);
    	}
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
		try {
    		ConfigManager cfg = ConfigManager.instance();
    		if(m_provider == null)
    			initProvider(cfg.getProperty("DIGIDOC_SIGN_PKCS11_DRIVER"), pin, token);
    		if(m_keyStore == null)
    			initKeystore(pin);
    		if(m_keyStore == null) {
    			m_logger.error("Failed to load keystore");
    			throw new DigiDocException(DigiDocException.ERR_TOKEN_LOGIN, "Keystore load failed", null);
    		}
    		try {
    			if(m_logger.isDebugEnabled())
	    			m_logger.debug("Decrypting: " + ConvertUtils.bin2hex(data) + " len: " + data.length + " with: " + m_alias + " on: " + m_provider.getName());
    			Cipher cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding");
                cipher.init(Cipher.DECRYPT_MODE, m_keyStore.getKey(m_alias, pin.toCharArray()));
                byte[] ddata = cipher.doFinal(data);
                if(m_logger.isDebugEnabled())
	    			m_logger.debug("Decrypted: " + ConvertUtils.bin2hex(ddata) + " len: " + ddata.length);
                return ddata;
            } catch (NoSuchPaddingException e) {
                throw new RuntimeException(e);
            } catch (InvalidKeyException e) {
                throw new RuntimeException(e);
            } catch (IllegalBlockSizeException e) {
                throw new RuntimeException(e);
            } catch (BadPaddingException e) {
                // More likely bad password
            	throw new DigiDocException(DigiDocException.ERR_TOKEN_LOGIN, "Invalid PIN", e);
            }
    	} catch(Exception ex) {
    		m_logger.error("Error init provider: " + ex);
    		ex.printStackTrace();
    	}
    	return null;
	}
				
	/**
	 * Returns signature factory type identifier
	 * @return factory type identifier
	 */
	public String getType()
	{
		return SIGFAC_TYPE_PKCS11_SUN;
	}
	
}
