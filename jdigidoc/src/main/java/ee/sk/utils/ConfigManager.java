/*
 * ConfigManager.java
 * PROJECT: JDigiDoc
 * DESCRIPTION: Digi Doc functions for creating
 *	and reading signed documents. 
 * AUTHOR:  Veiko Sinivee, S|E|B IT Partner Estonia
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
package ee.sk.utils;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Properties;
import java.util.Hashtable;
import java.io.InputStream;
import java.io.FileInputStream;
import java.net.URL;
import ee.sk.digidoc.factory.SignatureFactory;
import ee.sk.digidoc.factory.NotaryFactory;
import ee.sk.digidoc.factory.DigiDocFactory;
import ee.sk.digidoc.factory.CanonicalizationFactory;
import ee.sk.digidoc.factory.TimestampFactory;
import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.SignedDoc;
import ee.sk.xmlenc.factory.EncryptedDataParser;
import ee.sk.xmlenc.factory.EncryptedStreamParser;
import ee.sk.digidoc.factory.TrustServiceFactory;

// Logging classes
import org.apache.log4j.PropertyConfigurator;
import org.apache.log4j.Logger;

/**
 * Configuration reader for JDigiDoc
 */
public class ConfigManager {
    /** Resource bundle */
    private static Properties m_props = null;
    /** singleton instance */
    private static ConfigManager m_instance = null;
    /** notary factory instance */
    private static NotaryFactory m_notFac = null;
    /** canonicalization factory instance */
    private static CanonicalizationFactory m_canFac = null;
    /** timestamp factory implementation */
    private static TimestampFactory m_tsFac = null;
    
    /** log4j logger */
    private static Logger m_logger = Logger.getLogger(ConfigManager.class);
    private static SignatureFactory m_sigFac = null;
    private static TrustServiceFactory m_tslFac = null;
    
    /**
     * Singleton accessor
     */
    public static ConfigManager instance() {
        if(m_instance == null)
            m_instance = new ConfigManager();
        return m_instance;
    }
    
    /**
     * ConfigManager default constructor
     */
    private ConfigManager() {
    	// initialize logging
    	if(getProperty("DIGIDOC_LOG4J_CONFIG") != null) {
    		PropertyConfigurator.configure(getProperty("DIGIDOC_LOG4J_CONFIG"));
    	}
    	m_logger = Logger.getLogger(ConfigManager.class);
    }
    
    /**
     * Resets the configuration table
     */
    public void reset() {
    	m_props = new Properties();
    }
    
    /**
	 * Checks if this certificate has non-repudiation bit set
	 * @param cert X509Certificate object
	 * @return true if ok
	 */
	public static boolean isSignatureKey(X509Certificate cert)
	{
		if(cert != null) {
			boolean keyUsages[] = cert.getKeyUsage();
			if(keyUsages != null && keyUsages.length > 2 && keyUsages[1] == true)
				return true;
		}
		return false;
	}
	
    /**
     * Add provider used in many methods of this library
     */
    public static Provider addProvider()
    {
    	try {
    		String s = ConfigManager.
                    instance().getStringProperty("DIGIDOC_SECURITY_PROVIDER", 
                    		"org.bouncycastle.jce.provider.BouncyCastleProvider");
    		Provider prv = (Provider)Class.forName(ConfigManager.
                    instance().getStringProperty("DIGIDOC_SECURITY_PROVIDER", 
                    		"org.bouncycastle.jce.provider.BouncyCastleProvider")).newInstance();
            Security.addProvider(prv);
            return prv;
    	} catch(Exception ex) {
    		m_logger.error("Error adding provider: " + ex);
    	}
    	return null;
    }
         
    /**
     * Init method for reading the config data
     * from a properties file. Note that this method
     * doesn't reset the configuration table held in
     * memory. Thus you can use it multpile times and
     * add constantly new configuration entries. Use the
     * reset() method to reset the configuration table.
     * @param cfgFileName config file anme or URL
     * @return success flag
     */
    public static boolean init(String cfgFileName) {
    	boolean bOk = false;
        try {
        	if(m_props == null)
        		m_props = new Properties();
            InputStream isCfg = null;
            URL url = null;
            if(cfgFileName.startsWith("http")) {
                url = new URL(cfgFileName);
                isCfg = url.openStream();
            } else if(cfgFileName.startsWith("jar://")) {
            	ClassLoader cl = ConfigManager.class.getClassLoader();
                isCfg = cl.getResourceAsStream(cfgFileName.substring(6));
            } else {
                isCfg = new FileInputStream(cfgFileName);
            }
            m_props.load(isCfg);
            isCfg.close();
            url = null; 
			bOk = true;
        } catch (Exception ex) {            
            m_logger.error("Cannot read config file: " + 
                cfgFileName + " Reason: " + ex.toString());
        }
        // initialize
        return bOk;
    }
         
    /**
     * Init method for settings the config data
     * from a any user defined source
     * @param hProps config data
     */
    public static void init(Hashtable hProps) {
    	m_props = new Properties();
      	m_props.putAll(hProps);
    }
    
    /**
     * Returns the SignatureFactory instance
     * @return SignatureFactory implementation
     */
    public SignatureFactory getSignatureFactory()
        throws DigiDocException
    {
    	try {
        	if(m_sigFac == null) {
        		m_sigFac = (SignatureFactory)Class.
                    forName(getProperty("DIGIDOC_SIGN_IMPL")).newInstance();
        		if(m_sigFac != null) {
        			m_sigFac.init();
        			
        		}
        	}
        } catch(DigiDocException ex) {
            throw ex;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_INIT_SIG_FAC);
        }
        return m_sigFac;
    }
    
    /**
     * Returns the SignatureFactory instance
     * @return SignatureFactory implementation
     */
    public SignatureFactory getSignatureFactoryOfType(String sType)
        throws DigiDocException
    {
    	try {
    		SignatureFactory sFac = null;
    		if(SignatureFactory.SIGFAC_TYPE_PKCS11.equals(sType))
    			sFac = (SignatureFactory)Class.
                    forName(getProperty("DIGIDOC_SIGN_IMPL_PKCS11")).newInstance();
    		if(SignatureFactory.SIGFAC_TYPE_PKCS12.equals(sType))
    			sFac = (SignatureFactory)Class.
                    forName(getProperty("DIGIDOC_SIGN_IMPL_PKCS12")).newInstance();
    		if(sFac != null) 
        		sFac.init();
        	return sFac;
        } catch(DigiDocException ex) {
            throw ex;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_INIT_SIG_FAC);
        }
        return m_sigFac;
    }
    
    /**
     * Returns the TrustServiceFactory instance
     * @return TrustServiceFactory implementation
     */
    public TrustServiceFactory getTslFactory()
        throws DigiDocException
    {
    	try {
        	if(m_tslFac == null) {
        		m_tslFac = (TrustServiceFactory)Class.
                    forName(getProperty("DIGIDOC_TSLFAC_IMPL")).newInstance();
        		if(m_tslFac != null) {
        			m_tslFac.init();
        		}
        	}
        } catch(DigiDocException ex) {
            throw ex;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_INIT_SIG_FAC);
        }
        return m_tslFac;
    }
    
    /**
     * Returns the SignatureFactory instance
     * @param type type of signature factory
     * @return SignatureFactory implementation
     */
    public SignatureFactory getSignatureFactory(String type)
        throws DigiDocException
    {
    	SignatureFactory sigFac = null;
    	try {
        	String strClass = getProperty("DIGIDOC_SIGN_IMPL_" + type);
        	if(strClass != null) {
        		sigFac = (SignatureFactory)Class.
                    forName(strClass).newInstance();
        		if(sigFac != null) {
        			if(sigFac.getType().equals(SignatureFactory.SIGFAC_TYPE_PKCS11))
        				sigFac.init();
        		}
        	}
        	if(sigFac == null)
        		throw new DigiDocException(DigiDocException.ERR_INIT_SIG_FAC, "No signature factory of type: " + type, null);
        } catch(DigiDocException ex) {
            throw ex;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_INIT_SIG_FAC);
        }
        return sigFac;
    }

    /**
     * Returns the NotaryFactory instance
     * @return NotaryFactory implementation
     */
    public NotaryFactory getNotaryFactory()
        throws DigiDocException
    {
        try {
            if(m_notFac == null) {
                m_notFac = (NotaryFactory)Class.
                    forName(getProperty("DIGIDOC_NOTARY_IMPL")).newInstance();
                m_notFac.init();
            }
        } catch(DigiDocException ex) {
            throw ex;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_NOT_FAC_INIT);
        }
        return m_notFac;
    }

    /**
     * Returns the TimestampFactory instance
     * @return TimestampFactory implementation
     */
    public TimestampFactory getTimestampFactory()
        throws DigiDocException
    {
        try {
            if(m_tsFac == null) {
            	m_tsFac = (TimestampFactory)Class.
                    forName(getProperty("DIGIDOC_TIMESTAMP_IMPL")).newInstance();
            	m_tsFac.init();
            }
        } catch(DigiDocException ex) {
            throw ex;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_TIMESTAMP_FAC_INIT);
        }
        return m_tsFac;
    }

    /**
     * Returns the DigiDocFactory instance
     * @return DigiDocFactory implementation
     */
    public DigiDocFactory getDigiDocFactory()
        throws DigiDocException
    {
    	DigiDocFactory ddocFac = null;
    	try {
    		ddocFac = (DigiDocFactory)Class.
                    forName(getProperty("DIGIDOC_FACTORY_IMPL")).newInstance();
    		ddocFac.init(); 
        } catch(DigiDocException ex) {
            throw ex;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_DIG_FAC_INIT);
        }
        return ddocFac;
    }
    
    
    /**
     * Returns the CanonicalizationFactory instance
     * @return CanonicalizationFactory implementation
     */
    public CanonicalizationFactory getCanonicalizationFactory()
        throws DigiDocException
    {
        try {
            if(m_canFac == null) {
                m_canFac = (CanonicalizationFactory)Class.
                    forName(getProperty("CANONICALIZATION_FACTORY_IMPL")).newInstance();
                m_canFac.init();
            }
        } catch(DigiDocException ex) {
            throw ex;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_CAN_FAC_INIT);
        }
        return m_canFac;
    }

	/**
	 * Returns the EncryptedDataParser instance
	 * @return EncryptedDataParser implementation
	 */
	public EncryptedDataParser getEncryptedDataParser()
		throws DigiDocException
	{
		EncryptedDataParser dencFac = null;
		try {
			dencFac = (EncryptedDataParser)Class.
					forName(getProperty("ENCRYPTED_DATA_PARSER_IMPL")).newInstance();
			dencFac.init();            
		} catch(DigiDocException ex) {
			throw ex;
		} catch(Exception ex) {
			DigiDocException.handleException(ex, DigiDocException.ERR_DIG_FAC_INIT);
		}
		return dencFac;
	}

	/**
	 * Returns the EncryptedStreamParser instance
	 * @return EncryptedStreamParser implementation
	 */
	public EncryptedStreamParser getEncryptedStreamParser()
		throws DigiDocException
	{
		EncryptedStreamParser dstrFac = null;
		try {
			dstrFac = (EncryptedStreamParser)Class.
					forName(getProperty("ENCRYPTED_STREAM_PARSER_IMPL")).newInstance();
			dstrFac.init();            
		} catch(DigiDocException ex) {
			throw ex;
		} catch(Exception ex) {
			DigiDocException.handleException(ex, DigiDocException.ERR_DIG_FAC_INIT);
		}
		return dstrFac;
	}
   
    /**
     * Retrieves the value for the spcified key
     * @param key property name
     */
    public String getProperty(String key) {
        return m_props.getProperty(key);        
    }
   
    /**
     * Retrieves a string value for the specified key
     * @param key property name
     * @param def default value
     */
    public String getStringProperty(String key, String def) {
        return m_props.getProperty(key, def);        
    }
    
    public void setStringProperty(String key, String value) {
    	if(m_props != null)
    		m_props.put(key, value);
    }
   
    /**
     * Retrieves an int value for the specified key
     * @param key property name
     * @param def default value
     */
    public int getIntProperty(String key, int def) {
        int rc = def;
        try {
        	String s = m_props.getProperty(key);
        	if(s != null && s.trim().length() > 0)
        		rc = Integer.parseInt(s);    
        } catch(NumberFormatException ex) {
            m_logger.error("Error parsing number: " + key, ex);
        }
        return rc;
    }

    /**
     * Retrieves a long value for the specified key
     * @param key property name
     * @param def default value
     */
    public long getLongProperty(String key, long def) {
    	long rc = def;
        try {
        	String s = m_props.getProperty(key);
        	if(s != null && s.trim().length() > 0)
        		rc = Long.parseLong(s);    
        } catch(NumberFormatException ex) {
            m_logger.error("Error parsing number: " + key, ex);
        }
        return rc;
    }
    
    /**
     * Retrieves a boolean value for the specified key
     * @param key property name
     * @param def default value
     */
    public boolean getBooleanProperty(String key, boolean def) {
    	boolean rc = def;
        try {
        	String s = m_props.getProperty(key);
        	if(s != null) {
        		if(s.trim().equalsIgnoreCase("TRUE"))
        		   rc = true;  
        		if(s.trim().equalsIgnoreCase("FALSE"))
         		   rc = false;
        	}
        } catch(NumberFormatException ex) {
            m_logger.error("Error parsing boolean: " + key, ex);
        }
        return rc;
    }
    
    /**
     * Returns default digest type value
     * @param sdoc SignedDoc object
     * @return default digest type
     */
    public String getDefaultDigestType(SignedDoc sdoc)
    {
    	if(sdoc != null && sdoc.getFormat() != null && sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC))
    		return getStringProperty("DIGIDOC_DIGEST_TYPE", SignedDoc.SHA256_DIGEST_TYPE);
    	else
    		return SignedDoc.SHA1_DIGEST_TYPE;
    }
    
    /**
     * Returns digest algorithm URI corresponding to
     * searched digest type value
     * @param digType digest type
     * @return digest algorithm URI
     */
    public static String digType2Alg(String digType)
    {
    	if(digType != null) {
    		if(digType.equals(SignedDoc.SHA1_DIGEST_TYPE))
    			return SignedDoc.SHA1_DIGEST_ALGORITHM;
    		if(digType.equals(SignedDoc.SHA224_DIGEST_TYPE))
    			return SignedDoc.SHA224_DIGEST_ALGORITHM;
    		if(digType.equals(SignedDoc.SHA256_DIGEST_TYPE))
    			return SignedDoc.SHA256_DIGEST_ALGORITHM_1;
    		if(digType.equals(SignedDoc.SHA384_DIGEST_TYPE))
    			return SignedDoc.SHA384_DIGEST_ALGORITHM;
    		if(digType.equals(SignedDoc.SHA512_DIGEST_TYPE))
    			return SignedDoc.SHA512_DIGEST_ALGORITHM;
    	}
    	return null;
    }
    
    /**
     * Returns signature method URI corresponding to
     * searched digest type value
     * @param digType digest type
     * @return signature method URI
     */
    public static String digType2SigMeth(String digType, boolean isEC)
    {
    	if(digType != null) {
    		if(isEC) {
        		if(digType.equals(SignedDoc.SHA1_DIGEST_TYPE))
        			return SignedDoc.ECDSA_SHA1_SIGNATURE_METHOD;
        		if(digType.equals(SignedDoc.SHA224_DIGEST_TYPE))
        			return SignedDoc.ECDSA_SHA224_SIGNATURE_METHOD;
        		if(digType.equals(SignedDoc.SHA256_DIGEST_TYPE))
        			return SignedDoc.ECDSA_SHA256_SIGNATURE_METHOD;
        		if(digType.equals(SignedDoc.SHA384_DIGEST_TYPE))
        			return SignedDoc.ECDSA_SHA384_SIGNATURE_METHOD;
        		if(digType.equals(SignedDoc.SHA512_DIGEST_TYPE))
        			return SignedDoc.ECDSA_SHA512_SIGNATURE_METHOD;    			
    		} else {
    		if(digType.equals(SignedDoc.SHA1_DIGEST_TYPE))
    			return SignedDoc.RSA_SHA1_SIGNATURE_METHOD;
    		if(digType.equals(SignedDoc.SHA224_DIGEST_TYPE))
    			return SignedDoc.RSA_SHA224_SIGNATURE_METHOD;
    		if(digType.equals(SignedDoc.SHA256_DIGEST_TYPE))
    			return SignedDoc.RSA_SHA256_SIGNATURE_METHOD;
    		if(digType.equals(SignedDoc.SHA384_DIGEST_TYPE))
    			return SignedDoc.RSA_SHA384_SIGNATURE_METHOD;
    		if(digType.equals(SignedDoc.SHA512_DIGEST_TYPE))
    			return SignedDoc.RSA_SHA512_SIGNATURE_METHOD;
    		}
    	}
    	return null;
    }
    
    /**
     * Returns signature method URI corresponding to
     * searched digest type value
     * @param digType digest type
     * @return signature method URI
     */
    public static String sigMeth2SigType(String sigMeth)
    {
    	if(sigMeth != null) {
    		if(sigMeth.equals(SignedDoc.ECDSA_SHA1_SIGNATURE_METHOD))
        		return "SHA1withCVC-ECDSA";
        	if(sigMeth.equals(SignedDoc.ECDSA_SHA224_SIGNATURE_METHOD))
        		return "SHA224withCVC-ECDSA";
       		if(sigMeth.equals(SignedDoc.ECDSA_SHA256_SIGNATURE_METHOD))
       			return "SHA256withCVC-ECDSA";
       		if(sigMeth.equals(SignedDoc.ECDSA_SHA384_SIGNATURE_METHOD))
       			return "SHA384withCVC-ECDSA";
       		if(sigMeth.equals(SignedDoc.ECDSA_SHA512_SIGNATURE_METHOD))
        		return "SHA512withCVC-ECDSA";    			
    		if(sigMeth.equals(SignedDoc.RSA_SHA1_SIGNATURE_METHOD))
    			return "SHA1withRSA";
    		if(sigMeth.equals(SignedDoc.RSA_SHA224_SIGNATURE_METHOD))
    			return "SHA224withRSA";
    		if(sigMeth.equals(SignedDoc.RSA_SHA256_SIGNATURE_METHOD))
    			return "SHA256withRSA";
    		if(sigMeth.equals(SignedDoc.RSA_SHA384_SIGNATURE_METHOD))
    			return "SHA384withRSA";
    		if(sigMeth.equals(SignedDoc.RSA_SHA512_SIGNATURE_METHOD))
    			return "SHA512withRSA";
    	}
    	return null;
    }
    
    /**
     * Returns digest type for given algorithm URI
     * @param digAlg digest algorithm URI
     * @return digest type
     */
    public static String digAlg2Type(String digAlg)
    {
    	if(digAlg != null) {
    		if(digAlg.equals(SignedDoc.SHA1_DIGEST_ALGORITHM))
    			return SignedDoc.SHA1_DIGEST_TYPE;
    		if(digAlg.equals(SignedDoc.SHA224_DIGEST_ALGORITHM))
    			return SignedDoc.SHA224_DIGEST_TYPE;
    		if(digAlg.equals(SignedDoc.SHA256_DIGEST_ALGORITHM_1) ||
    			digAlg.equals(SignedDoc.SHA256_DIGEST_ALGORITHM_2))
    			return SignedDoc.SHA256_DIGEST_TYPE;
    		if(digAlg.equals(SignedDoc.SHA384_DIGEST_ALGORITHM))
    			return SignedDoc.SHA384_DIGEST_TYPE;
    		if(digAlg.equals(SignedDoc.SHA512_DIGEST_ALGORITHM))
    			return SignedDoc.SHA512_DIGEST_TYPE;
    	}
    	return null;
    }
    
    /**
     * Returns digest type for given signature method URI
     * @param sigMeth signature method algorithm URI
     * @return digest type
     */
    public static String sigMeth2Type(String sigMeth)
    {
    	if(sigMeth != null) {
    		if(sigMeth.equals(SignedDoc.RSA_SHA1_SIGNATURE_METHOD))
    			return SignedDoc.SHA1_DIGEST_TYPE;
    		if(sigMeth.equals(SignedDoc.RSA_SHA224_SIGNATURE_METHOD))
    			return SignedDoc.SHA224_DIGEST_TYPE;
    		if(sigMeth.equals(SignedDoc.RSA_SHA256_SIGNATURE_METHOD))
    			return SignedDoc.SHA256_DIGEST_TYPE;
    		if(sigMeth.equals(SignedDoc.RSA_SHA384_SIGNATURE_METHOD))
    			return SignedDoc.SHA384_DIGEST_TYPE;
    		if(sigMeth.equals(SignedDoc.RSA_SHA512_SIGNATURE_METHOD))
    			return SignedDoc.SHA512_DIGEST_TYPE;
    		if(sigMeth.equals(SignedDoc.ECDSA_SHA1_SIGNATURE_METHOD))
        		return SignedDoc.SHA1_DIGEST_TYPE;
        	if(sigMeth.equals(SignedDoc.ECDSA_SHA224_SIGNATURE_METHOD))
        		return SignedDoc.SHA224_DIGEST_TYPE;
       		if(sigMeth.equals(SignedDoc.ECDSA_SHA256_SIGNATURE_METHOD))
       			return SignedDoc.SHA256_DIGEST_TYPE;
       		if(sigMeth.equals(SignedDoc.ECDSA_SHA384_SIGNATURE_METHOD))
       			return SignedDoc.SHA384_DIGEST_TYPE;
       		if(sigMeth.equals(SignedDoc.ECDSA_SHA512_SIGNATURE_METHOD))
        		return SignedDoc.SHA512_DIGEST_TYPE;
    	}
    	return null;
    }
    
}
