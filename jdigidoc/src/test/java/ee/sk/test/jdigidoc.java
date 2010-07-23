/*
 * jdigidoc.java
 * PROJECT: JDigiDoc
 * DESCRIPTION: Generic test programm for JDigiDoc library. 
 * Provides a command-line interface to most features of the library.
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

package ee.sk.test;
import ee.sk.digidoc.*;
import ee.sk.xmlenc.*;
import ee.sk.xmlenc.factory.*;
import java.io.*;
import java.net.InetAddress;
import java.net.NetworkInterface;

import ee.sk.digidoc.factory.*;
import ee.sk.utils.*;

import java.util.*;
import java.security.cert.X509Certificate;

/**
 * jdigidoc is a small command-line programm providing
 * an interface to most of the librarys functionality and 
 * also documenting the library and serving as sample
 * code for other developers.
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class jdigidoc {
	/** signed doc object if used */
	private SignedDoc m_sdoc;
	/** encrypted data object if used */
	private EncryptedData m_cdoc;
	String sFilIn, sFilOut;
	
	/**
	 * Constructor for jdigidoc
	 */
	public jdigidoc()
	{
		m_sdoc = null;
		m_cdoc = null;
	}

	/**
	 * Checks for commands related to
	 * creating signed documents
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runNewSignedDocCmds(String[] args)
	{
		boolean bFound = false, bOk = true;
		String format = SignedDoc.FORMAT_DIGIDOC_XML;
		String version = null, ver = null, profile = null;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-ddoc-new")) {
				bFound = true;
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					format = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					version = args[i+1];
					i++;
				}
			}
		}
		if(bFound) {
			try {
				// this profile & version logic is really done in DigiDocGenFactory.createSignedDoc()
				profile = version;
				//ver = version;
				if(format != null && format.equals(SignedDoc.FORMAT_BDOC)) {
					if(ver == null)
						ver = SignedDoc.BDOC_VERSION_2_1;
					if(profile != null && profile.equals("TS")) {
						System.out.println("TS profile is currently not supported!");
						return false;
					}
					if(profile != null && version.equals(SignedDoc.BDOC_VERSION_2_1)) {
						profile = SignedDoc.BDOC_PROFILE_TM;
					}
					// if profile is not set then lookup default profile from config
					// if not set in config use TM as default
					if(profile == null || profile.trim().length() == 0) 
						profile = ConfigManager.instance().getStringProperty("DIGIDOC_DEFAULT_PROFILE", SignedDoc.BDOC_PROFILE_TM);
				}
				if(format != null && (format.equals(SignedDoc.FORMAT_SK_XML) || format.equals(SignedDoc.FORMAT_DIGIDOC_XML))) {
					if(ver == null)
						ver = SignedDoc.VERSION_1_3;
					profile = SignedDoc.BDOC_PROFILE_TM; // in ddoc format we used only TM
				}
				System.out.println("Creating digidoc: " + format + " / " + ver + " / " + profile);
				m_sdoc = new SignedDoc(format, ver);
				m_sdoc.setProfile(profile);
				//m_sdoc = DigiDocGenFactory.createSignedDoc(format, version, version);
			} catch(Exception ex) {
				bOk = false;
				System.err.println("ERROR: creating digidoc format: " + format + " / " + version + " - " + ex);
				ex.printStackTrace(System.err);
			}
		}			
		return bOk; // nothing to do?
	}

	/**
	 * Checks for commands related to
	 * writing signed documents
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runWriteSignedDocCmds(String[] args)
	{
		boolean bOk = true, bFound = false, bStream = false, bOStream = false;
		String outFile = null;
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-ddoc-out") || args[i].equals("-ddoc-out-stream") || args[i].equals("-ddoc-out-ostream")) {
				bFound = true;
				if(args[i].equals("-ddoc-out-stream"))
					bStream = true;
				if(args[i].equals("-ddoc-out-ostream"))
					bOStream = true;
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					sFilOut = outFile = args[i+1];
					i++;
				} else {
					bOk = false;
					System.err.println("Missing output file of -ddoc-out command");
				}
			}
		}
		//System.out.println("Out: " + outFile + " found: " + bFound);
		if(bFound && outFile != null) {
			try {
				if(m_sdoc == null) {
					System.err.println("No signed document to sign. Use -ddoc-in or -ddoc-new commands!");
					return false;
				}
				if(bOStream) {
					ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(outFile));
					oos.writeObject(m_sdoc);
					oos.close();
				} else if(bStream) {
					FileOutputStream fos = new FileOutputStream(outFile);
					m_sdoc.writeToStream(fos);
					fos.close();
				} else {
					//System.out.println("write: " + outFile);
					m_sdoc.writeToFile(new File(outFile));  
				}
				bOk = true;
			} catch(Exception ex) {
				bOk = false;
				System.err.println("ERROR: writing digidoc: " + ex);
				ex.printStackTrace(System.err);
			}
		}
		return bOk; // nothing to do?
	}
	
	/**
	 * Checks for commands related to
	 * signing signed documents
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runSignSignedDocCmds(String[] args)
	{
		boolean bOk = true;
		String sImpl = null;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-ddoc-sign")) {
				String pin = null;
				String rollReso = null;
				String country = null;
				String city = null;
				String state = null;
				String zip = null;
				String profile = null;
				String keystoreFile = null;
				int nSlot = 0;
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					pin = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					rollReso = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					country = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					state = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					city = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					zip = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					nSlot = Integer.parseInt(args[i+1]);
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					profile = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					sImpl = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					keystoreFile = args[i+1];
					i++;
				}
				if(pin != null) {
					try {
						if(m_sdoc == null) {
							System.err.println("No signed document to sign. Use -ddoc-in or -ddoc-new commands!");
							return false;
						}
						// roll/resolutsioon
						String[] roles = null;
						if(rollReso != null && rollReso.trim().length() > 0) {
						  roles = new String[1];
						  roles[0] = rollReso;
						}
						// address
						SignatureProductionPlace adr = null;
						if(country != null || state != null || city != null || zip != null)
							adr = new SignatureProductionPlace(city, state, country, zip);
						System.out.println("Signing digidoc");
						ConfigManager cfg = ConfigManager.instance();
						System.err.println("Signing of type: " + sImpl);
						SignatureFactory sigFac = null;
						ArrayList lerrs = null;
						// check old vers
						DigiDocException ex1 = m_sdoc.validateFormatAndVersion();
				    	if(ex1 != null) {
				    		System.err.println("Validation error: " + ex1 + ". Signing cancelled!");
				    		return false;
				    	}
						if(sImpl != null) {
							if(sImpl.equals(SignatureFactory.SIGFAC_TYPE_PKCS11)) {
								sigFac = cfg.getSignatureFactoryOfType(sImpl);
								// default pkcs11 has no additional params
							} else if(sImpl.equals(SignatureFactory.SIGFAC_TYPE_PKCS12)) {
								sigFac = cfg.getSignatureFactoryOfType(sImpl);
							  Pkcs12SignatureFactory p12sfac = (Pkcs12SignatureFactory)sigFac;
							  if(keystoreFile == null || keystoreFile.trim().length() == 0)
								  keystoreFile = cfg.getProperty("DIGIDOC_KEYSTORE_FILE");
							  if(pin == null || pin.trim().length() == 0)
								  pin = cfg.getProperty("DIGIDOC_KEYSTORE_PASSWD");
							  bOk = p12sfac.load(keystoreFile, SignatureFactory.SIGFAC_TYPE_PKCS12, pin);
							} else {
								System.err.println("No signature factory of type: " + sImpl);
								return false;
							}
						} else {
							sigFac = cfg.getSignatureFactory();
							if(sigFac.getType().equals(SignatureFactory.SIGFAC_TYPE_PKCS12)) {
								  Pkcs12SignatureFactory p12sfac = (Pkcs12SignatureFactory)sigFac;
								  if(keystoreFile == null || keystoreFile.trim().length() == 0)
									  keystoreFile = cfg.getProperty("DIGIDOC_KEYSTORE_FILE");
								  if(pin == null || pin.trim().length() == 0)
									  pin = cfg.getProperty("DIGIDOC_KEYSTORE_PASSWD");
								  bOk = p12sfac.load(keystoreFile, SignatureFactory.SIGFAC_TYPE_PKCS12, pin);
							} 
						}
						if(!bOk) {
							System.out.println("Failed to load signature token!");
							return bOk;
						}
						System.out.println("GET Cert in slot: " + nSlot + " cmd-profile: " + profile);
						X509Certificate cert = sigFac.getCertificate(nSlot, pin);
						if(profile == null)
							profile = m_sdoc.getProfile();
						if(profile != null && (m_sdoc.getProfile() == null || !m_sdoc.getProfile().equals(profile))) {
							if(profile.equals("TM.v21")) {
								m_sdoc.setProfile(SignedDoc.BDOC_PROFILE_TM);
								m_sdoc.setVersion(SignedDoc.BDOC_VERSION_2_1);
							} else {
								if(m_sdoc.getProfile() == null || m_sdoc.getProfile().trim().length() == 0 || m_sdoc.getProfile().trim().equalsIgnoreCase("BES"))
									m_sdoc.setProfile(profile);
							}
						}
						//System.out.println("Prepare signature, cert: " + ((cert != null) ? "OK" : "NULL") + " status: " + bOk + " container-profile: " + profile);
						Signature sig = m_sdoc.prepareSignature(cert, roles, adr);
						if(profile == null || profile.trim().length() == 0 || profile.trim().equalsIgnoreCase("BES"))
							profile = ConfigManager.instance().getStringProperty("DIGIDOC_DEFAULT_PROFILE", "TM");
						System.out.println("Prepare signature, cert: " + ((cert != null) ? "OK" : "NULL") + " status: " + bOk + " cfg-profile: " + profile + " sig-profile: " + sig.getProfile());
						if(profile != null && (sig.getProfile() == null || !profile.startsWith(sig.getProfile()))) {
							sig.setProfile(profile);
							if(m_sdoc.getProfile() == null || m_sdoc.getProfile().trim().length() == 0 || m_sdoc.getProfile().trim().equalsIgnoreCase("BES"))
								m_sdoc.setProfile(profile);
						}
						if(profile != null && profile.trim().equals("TS")) {
							System.out.println("TS profile is currently not supported!");
							return false;
						}
						byte[] sidigest = null;
						if(sigFac.getType().equals(SignatureFactory.SIGFAC_TYPE_PKCS11))
						  sidigest = sig.calculateSignedInfoDigest();
						if(sigFac.getType().equals(SignatureFactory.SIGFAC_TYPE_PKCS12))
						  sidigest = sig.calculateSignedInfoXML();
						System.out.println("Create signature, cert: " + ((cert != null) ? "OK" : "NULL") + " status: " + bOk + " sig-profile: " + sig.getProfile());
						
						byte[] sigval = sigFac.sign(sidigest, nSlot, pin, sig);
						// finalize signature up to default profile
						System.out.println("Finalize signature: " + sig.getId() + " profile: " + sig.getProfile() + " sig-len: " + ((sigval != null) ? sigval.length : 0));
						sig.setSignatureValue(sigval);
						// set HTTP_FROM to some value
						sig.setHttpFrom(composeHttpFrom());
						if(sig.getProfile().trim().equals(SignedDoc.BDOC_PROFILE_TM) ||
						   sig.getProfile().equals(SignedDoc.BDOC_PROFILE_TS) ||
						   sig.getProfile().equals(SignedDoc.BDOC_PROFILE_TSA) ||
					       sig.getProfile().equals(SignedDoc.BDOC_PROFILE_T) ||
					       sig.getProfile().equals(SignedDoc.BDOC_PROFILE_CL) ||
					       sig.getProfile().equals(SignedDoc.BDOC_PROFILE_TMA))
						sig.getConfirmation();
						
					} catch(Exception ex) {
						bOk = false;
						System.err.println("ERROR signing: " + ex);
						ex.printStackTrace(System.err);
					}
				} else {
					bOk = false;
					System.err.println("Missing pin of -ddoc-sign command");
				}
			}
		}
		return bOk; // nothing to do?
	}

	/**
	 * Checks for commands related to
	 * calculating signature value for later signing in online plugin etc.
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runCalcSignCmds(String[] args)
	{
		boolean bOk = true;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-ddoc-calc-sign")) {
				String certFile = null;
				String rollReso = null;
				String country = null;
				String city = null;
				String state = null;
				String zip = null;
				String profile = null;
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					certFile = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					rollReso = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					country = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					state = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					city = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					zip = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					profile = args[i+1];
					i++;
				}
				if(certFile != null) {
					try {
						if(m_sdoc == null) {
							System.err.println("No signed document to calc-sign. Use -ddoc-in or -ddoc-new commands!");
							return false;
						}
						// roll/resolutsioon
						String[] roles = null;
						if(rollReso != null && rollReso.trim().length() > 0) {
						  roles = new String[1];
						  roles[0] = rollReso;
						}
						// address
						SignatureProductionPlace adr = null;
						if(country != null || state != null || city != null || zip != null)
							adr = new SignatureProductionPlace(city, state, country, zip);
						System.out.println("Calculating signature");
						ConfigManager cfg = ConfigManager.instance();
						ArrayList lerrs = null;
						// check old vers
						DigiDocException ex1 = m_sdoc.validateFormatAndVersion();
				    	if(ex1 != null) {
				    		System.err.println("Validation error: " + ex1 + ". Signing cancelled!");
				    		return false;
				    	}
						System.out.println("GET Cert in file: " + certFile + " cmd-profile: " + profile);
						if(profile == null)
							profile = m_sdoc.getProfile();
						X509Certificate cert = m_sdoc.readCertificate(certFile);
						System.out.println("Prepare signature, cert: " + ((cert != null) ? "OK" : "NULL") + " status: " + bOk + " container-profile: " + profile);
						Signature sig = m_sdoc.prepareSignature(cert, roles, adr);
						if(profile == null || profile.trim().length() == 0 || profile.trim().equalsIgnoreCase("BES"))
							profile = ConfigManager.instance().getStringProperty("DIGIDOC_DEFAULT_PROFILE", "TM");
						System.out.println("Prepare signature, cert: " + ((cert != null) ? "OK" : "NULL") + " status: " + bOk + " cfg-profile: " + profile);
						if(profile != null && (sig.getProfile() == null || !sig.getProfile().equals(profile))) {
							sig.setProfile(profile);
							if(m_sdoc.getProfile() == null || m_sdoc.getProfile().trim().length() == 0 || m_sdoc.getProfile().trim().equalsIgnoreCase("BES"))
							  m_sdoc.setProfile(profile);
						}
						if(profile != null && profile.trim().equals("TS")) {
							System.out.println("TS profile is currently not supported!");
							return false;
						}
						byte[] sidigest = sig.calculateSignedInfoDigest();
						String sDigHex = ConvertUtils.bin2hex(sidigest);
						System.out.println("SignatureHash id: " + sig.getId() + " hash: " + sDigHex);
						
					} catch(Exception ex) {
						bOk = false;
						System.err.println("ERROR: calculating signature value: " + ex);
						ex.printStackTrace(System.err);
					}
				} else {
					bOk = false;
					System.err.println("Missing certFile of -ddoc-calc-sign command");
				}
			}
		}
		return bOk; // nothing to do?
	}

	/**
	 * Checks for commands related to
	 * adding hex signature value to signature without value and getting confirmation
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runAddSignValueCmds(String[] args)
	{
		boolean bOk = true;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-ddoc-add-sign-value")) {
				String signFile = null;
				String sigId = null;
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					signFile = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					sigId = args[i+1];
					i++;
				}
				if(signFile != null && sigId != null) {
					try {
						if(m_sdoc == null) {
							System.err.println("No signed document to calc-sign. Use -ddoc-in or -ddoc-new commands!");
							return false;
						}
						// read signature value
						byte[] bValHex = SignedDoc.readFile(new File(signFile));
						String sValHex = new String(bValHex).trim();
						System.out.println("Sign val: " + sValHex + " len: " + sValHex.length());
						byte[] sigval = ConvertUtils.hex2bin(sValHex);
						if(sigval == null || sigval.length < 128) {
							System.err.println("Must provide at least 128 bytes rsa signature value in hex encoding!");
				    		return false;
						}
						// find signature to finalize
						Signature sig = m_sdoc.findSignatureById(sigId);;
						if(sig == null) {
							System.err.println("No signature found with id: " + sigId);
				    		return false;
						}
						sig.setSignatureValue(sigval);
						System.out.println("Getting confirmation for signature: " + sig.getId());
						sig.getConfirmation();
						
					} catch(Exception ex) {
						bOk = false;
						System.err.println("ERROR: adding signature value: " + ex);
						ex.printStackTrace(System.err);
					}
				} else {
					bOk = false;
					System.err.println("Missing signFile or sigId of -ddoc-add-sign-value command");
				}
			}
		}
		return bOk; // nothing to do?
	}
	
	/**
	 * Checks for commands related to
	 * adding data files to signed documents
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runAddSignedDocCmds(String[] args)
	{
		boolean bOk = true;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-ddoc-add")) {
				String inFile = null;
				String inMime = null;
				String inContent = DataFile.CONTENT_EMBEDDED_BASE64;
				if(m_sdoc != null && m_sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC))
					inContent = DataFile.CONTENT_BINARY;
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					inFile = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					inMime = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					inContent = args[i+1];
					i++;
				}
				if(inFile != null && inMime != null) {
					try {
						if(m_sdoc == null) {
							System.out.println("Creating digidoc: " + SignedDoc.FORMAT_DIGIDOC_XML + ", " + SignedDoc.VERSION_1_3);
							m_sdoc = new SignedDoc(SignedDoc.FORMAT_DIGIDOC_XML, SignedDoc.VERSION_1_3);
						}
						System.out.println("Adding data-file: " + inFile + ", " + inMime + ", " + inContent);
						File f = new File(inFile);
						if(!f.isFile() && !f.canRead()) {
							System.err.println("File not found: " + inFile);
							return false;
						}
							//throw new DigiDocException(DigiDocException.ERR_DATA_FILE_FILE_NAME);
						DataFile df = m_sdoc.addDataFile(new File(inFile), inMime, inContent);
					} catch(Exception ex) {
						bOk = false;
						System.err.println("ERROR: adding DataFile: " + ex);
						ex.printStackTrace(System.err);
					}
				} else {
					bOk = false;
					System.err.println("Missing input file or mime type of -ddoc-add command");
				}
			}
		}
		return bOk; // nothing to do?
	}

	/**
	 * Checks for commands related to
	 * adding data files to signed documents from memory. Uses setBody()
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runAddMemSignedDocCmds(String[] args)
	{
		boolean bOk = true;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-ddoc-add-mem")) {
				String inFile = null;
				String inMime = null;
				String inContent = DataFile.CONTENT_EMBEDDED_BASE64;
				if(m_sdoc != null && m_sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC))
					inContent = DataFile.CONTENT_BINARY;
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					inFile = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					inMime = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					inContent = args[i+1];
					i++;
				}
				if(inFile != null && inMime != null) {
					try {
						if(m_sdoc == null) {
							System.out.println("Creating digidoc: " + SignedDoc.FORMAT_DIGIDOC_XML + ", " + SignedDoc.VERSION_1_3);
							m_sdoc = new SignedDoc(SignedDoc.FORMAT_DIGIDOC_XML, SignedDoc.VERSION_1_3);
						}
						System.out.println("Adding mem-data-file: " + inFile + ", " + inMime + ", " + inContent);
						File f = new File(inFile);
						if(!f.isFile() && !f.canRead()) {
							System.err.println("File not found: " + inFile);
							return false;
						}
						byte[] data = SignedDoc.readFile(f);
						DataFile df = new DataFile(m_sdoc.getNewDataFileId(), inContent, f.getName(), inMime, m_sdoc);
						df.setBody(data);
						m_sdoc.addDataFile(df);
					} catch(Exception ex) {
						bOk = false;
						System.err.println("ERROR: adding DataFile: " + ex);
						ex.printStackTrace(System.err);
					}
				} else {
					bOk = false;
					System.err.println("Missing input file or mime type of -ddoc-add command");
				}
			}
		}
		return bOk; // nothing to do?
	}

	private boolean isWarning(SignedDoc sdoc, DigiDocException ex)
	{
		if(ex != null && 
		  (ex.getCode() == DigiDocException.ERR_DF_INV_HASH_GOOD_ALT_HASH ||
		   ex.getCode() == DigiDocException.ERR_OLD_VER ||
		   ex.getCode() == DigiDocException.ERR_TEST_SIGNATURE ||
		   ex.getCode() == DigiDocException.WARN_WEAK_DIGEST ||
		  (ex.getCode() == DigiDocException.ERR_ISSUER_XMLNS && !sdoc.getFormat().equals(SignedDoc.FORMAT_SK_XML))))
			return true;
		return false;
	}
	
	private boolean hasNonWarningErrs(SignedDoc sdoc, ArrayList lerrs)
	{
		for(int i = 0; (lerrs != null) && (i < lerrs.size()); i++) {
			DigiDocException ex = (DigiDocException)lerrs.get(i);
			if(!isWarning(sdoc, ex)) {
			  return true;
			}
		}
		return false;
	}

	
	/**
	 * Checks for commands related to
	 * validating signed documents
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runValidateSignedDocCmds(String[] args)
	{
		boolean bFound = false, bOk = true, b = false, bLibErrs = false;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-ddoc-validate")) {
				bFound = true;
			}
			if(args[i].equals("-libraryerrors")) {
				bLibErrs = true;
			}
		}
		if(bFound) {
			if(m_sdoc != null) {
				System.out.println("Validating DigiDoc document: " + m_sdoc.getFormat() + "/" + m_sdoc.getVersion() + " profile: " + m_sdoc.getProfile());
				ArrayList lerrs = m_sdoc.verify(true, true);
				if(lerrs.size() > 0)
					printErrsAndWarnings(m_sdoc, lerrs, bLibErrs);
				if(SignedDoc.hasFatalErrs(lerrs))
					return false;
				bOk = !hasNonWarningErrs(m_sdoc, lerrs);
				// display data files
				for(int i = 0; i < m_sdoc.countDataFiles(); i++) {
					DataFile df = m_sdoc.getDataFile(i);
					System.out.println("\tDataFile: " + df.getId() + " file: " + df.getFileName() +
						" mime: " + df.getMimeType() + " size: " + df.getSize()); 
					ArrayList lerrs1 = new ArrayList();
					lerrs1 = df.validate(true);
					if(lerrs1.size() > 0)
					printErrsAndWarnings(m_sdoc, lerrs1, bLibErrs);
				}
				// display signatures
				for(int i = 0; i < m_sdoc.countSignatures(); i++) {
					Signature sig = m_sdoc.getSignature(i);
					System.out.println("\tSignature: " + sig.getId() + " profile: " + sig.getProfile());
					KeyInfo keyInfo = m_sdoc.getSignature(i).getKeyInfo();
					String userId = null, firstName = null, familyName = null, cn = null;
					//System.out.println("\tSignature: " + sig.getId() + " profile: " + sig.getProfile() + " key: " + ((keyInfo != null) ? "OK" : "NULL"));
					if(keyInfo != null) {
					  userId = keyInfo.getSubjectPersonalCode();
					  firstName = keyInfo.getSubjectFirstName();
					  familyName = keyInfo.getSubjectLastName();
					  if(keyInfo.getSignersCertificate() != null)
					  cn = SignedDoc.getCommonName(keyInfo.getSignersCertificate().getSubjectDN().getName());
					}
					ArrayList lerrs1 = new ArrayList();
					b = sig.verify(m_sdoc, lerrs1);
					X509Certificate cert = null;
					CertValue cv = sig.getCertValueOfType(CertValue.CERTVAL_TYPE_SIGNER);
					if(cv != null)
						cert = cv.getCert();
					if(cv != null && DigiDocGenFactory.isTestCard(cert)) {
						lerrs1.add(new DigiDocException(DigiDocException.ERR_TEST_SIGNATURE, "Test signature!", null));
					}
					
					System.out.print("\tSignature: " + sig.getId() + " profile: " + sig.getProfile() + " - ");
					System.out.print(cn);
					if(!b && hasNonWarningErrs(m_sdoc, lerrs1))
						System.out.println(" --> ERROR");
					else
						System.out.println(" --> OK"); 
					printErrsAndWarnings(m_sdoc, lerrs1, bLibErrs);
				}
			} else
				return false; // nothing read in to display
		}			
		return bOk; // nothing to do?
	}
	
	/**
	 * Checks for commands related to
	 * displaying signed documents
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runNotarizeSignedDocCmds(String[] args)
	{
		boolean bFound = false;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-ddoc-notarize")) {
				bFound = true;
				break;
			}
		}
		if(bFound) {
			if(m_sdoc != null) {
				System.out.println("Notarizing digidoc: ");
				// display signatures
				for(int i = 0; i < m_sdoc.countSignatures(); i++) {
					Signature sig = m_sdoc.getSignature(i);
					System.out.print("\tSignature: " + sig.getId() + " - ");
					KeyInfo keyInfo = m_sdoc.getSignature(i).getKeyInfo();
					String userId = keyInfo.getSubjectPersonalCode();
					String firstName = keyInfo.getSubjectFirstName();
					String familyName = keyInfo.getSubjectLastName();
					//String timeStamp = sdoc.getSignature(i).getSignedProperties().getSigningTime().toString();
					System.out.println(userId + "," + firstName + "," + familyName);
					// get confirmation
					try {
						sig.getConfirmation();
					} catch(DigiDocException ex) {
						System.out.println("ERROR: getting confirmation for: " + sig.getId() + 
								" - " + ex);
					}
					ArrayList errs = sig.verify(m_sdoc, false, true);
					if(errs.size() == 0)
						System.out.println(" --> OK");
					else
						System.out.println(" --> ERROR");
					for(int j = 0; j < errs.size(); j++) 
						System.out.println("\t\t" + (DigiDocException)errs.get(i));                
				}
			
			} else
				return false; // nothing read in to display
		}			
		return true; // nothing to do?
	}

	/**
	 * Checks for commands related to
	 * extracting data of signed files
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runExtractDataFileCmds(String[] args)
	{
		boolean bFound = false;
		String dfId = null, dfName = null;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-ddoc-extract")) {
				dfId = args[i+1];
				dfName = args[i+2];
				break;
			}
		}
		if(m_sdoc != null && dfId != null && dfName != null) {
			System.out.println("Search DF: " + dfId);
			// display signatures
			bFound = false;
			for(int i = 0; i < m_sdoc.countDataFiles(); i++) {
				DataFile df = m_sdoc.getDataFile(i);
				System.out.println("DF: " + i + " - " + df.getId());
                if(df.getId().equals(dfId)) {
                	try {
                		System.out.println("Extracting DF: " + dfId + " to: " + dfName);
                		FileOutputStream fos = new FileOutputStream(dfName);
                		InputStream is = df.getBodyAsStream();
                		if(is == null) {
                			System.err.println("DataFile has no data!");
                			return false;
                		}
                		byte[] data = new byte[4096];
                		int n = 0, m = 0;
                		while((n = is.read(data)) > 0) {
                			fos.write(data, 0, n);
                			m += n;
                		}
                		fos.close();
                		is.close();
                		bFound = true;
                		System.out.println("Wrote: " + m + " bytes to: " + dfName);
                	} catch(Exception ex) {
                		System.err.println("ERROR: extracting df: " + dfId + " - " + ex);
                	}
                }
			}
			if(!bFound)
				System.err.println("No datafile found: " + dfId);
			
		} 
		
		return true; // nothing to do?
	}
	
	/**
	 * Checks for commands related to
	 * removing signatures
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runRmvSigCmds(String[] args)
	{
		boolean bFound = false;
		String sigId = null;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-ddoc-rm-sig")) {
				sigId = args[i+1];
				break;
			}
		}
		if(m_sdoc != null && sigId != null) {
			System.out.println("Remove signature: " + sigId);
			// display signatures
			bFound = false;
			for(int i = 0; i < m_sdoc.countSignatures(); i++) {
				Signature sig = m_sdoc.getSignature(i);
				//System.out.println("Sig: " + i + " - " + sig.getId());
                if(sig.getId().equals(sigId)) {
                	try {
                		System.out.println("Removing signature: " + sigId);
                		m_sdoc.removeSignature(i);
                		bFound = true;
                	} catch(Exception ex) {
                		System.err.println("ERROR: removing signature: " + sigId + " - " + ex);
                	}
                }
			}
			if(!bFound) {
				System.err.println("No signature found: " + sigId);
				return false;
			}
		} 
		return true; // nothing to do?
	}
	
	
	/**
	 * Checks for commands related to
	 * removing data-files
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runRmvDfCmds(String[] args)
	{
		boolean bFound = false;
		String dfId = null;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-ddoc-rm-df")) {
				dfId = args[i+1];
				break;
			}
		}
		if(m_sdoc != null && dfId != null) {
			System.out.println("Remove data-file: " + dfId);
			// display datafiles
			bFound = false;
			for(int i = 0; i < m_sdoc.countDataFiles(); i++) {
				DataFile df = m_sdoc.getDataFile(i);
				System.out.println("DF: " + i + " - " + df.getId());
                if(df.getId().equals(dfId)) {
                	try {
                		//System.out.println("Removing data-file: " + dfId);
                		m_sdoc.removeDataFile(i);
                		bFound = true;
                	} catch(Exception ex) {
                		System.err.println("ERROR: removing data-file: " + dfId + " - " + ex);
                	}
                }
			}
			if(!bFound) {
				System.err.println("No data-file found: " + dfId);
				return false;
			}
		} 
		return true; // nothing to do?
	}
	
	/**
	 * Checks for commands related to
	 * displaying encrypted documents
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runListEncryptedDataCmds(String[] args)
	{
		boolean bFound = false;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-cdoc-list")) {
				bFound = true;
				break;
			}
		}
		if(bFound) {
			if(m_cdoc != null) {
				System.out.println("Encrypted document: ");
				// display data object
				System.out.print("\tEncryptedData "); 
				if(m_cdoc.getId() != null)
					System.out.print(" Id: " + m_cdoc.getId());
				if(m_cdoc.getType() != null)
					System.out.print(" type: " + m_cdoc.getType());
				if(m_cdoc.getMimeType() != null)
					System.out.print(" mime: " + m_cdoc.getMimeType());
				if(m_cdoc.getEncryptionMethod() != null)
					System.out.print(" algorithm: " + m_cdoc.getEncryptionMethod());
				System.out.println();
				// display meta data
				System.out.println("\tFORMAT: " + m_cdoc.getPropFormatName() +
						" VER: " + m_cdoc.getPropFormatVersion());
				System.out.println("\tLIBRARY: " + m_cdoc.getPropLibraryName() +
						" VER: " + m_cdoc.getPropLibraryVersion());
				int nFiles = m_cdoc.getPropOrigFileCount();
				for(int i = 0; i < nFiles; i++) {
					System.out.println("\tDF: " + m_cdoc.getPropOrigFileId(i) +
							" FILE: " + m_cdoc.getPropOrigFileName(i) +
							" SIZE: " + m_cdoc.getPropOrigFileSize(i) +
							" MIME: " + m_cdoc.getPropOrigFileMime(i));					
				}
				// display transport keys
				for(int i = 0; i < m_cdoc.getNumKeys(); i++) {
					EncryptedKey ekey = m_cdoc.getEncryptedKey(i);
					System.out.print("\tEncryptedKey");
					if(ekey.getId() != null)
						System.out.print(" Id: " + ekey.getId());
					if(ekey.getRecipient() != null)
						System.out.print(" Recipient: " + ekey.getRecipient());
					if(ekey.getKeyName() != null)
						System.out.print(" key-name: " + ekey.getKeyName());
					if(ekey.getCarriedKeyName() != null)
						System.out.print(" carried-key-name: " + ekey.getCarriedKeyName());
					if(ekey.getEncryptionMethod() != null)
						System.out.print("\n\t\talgorithm: " + ekey.getEncryptionMethod());
					if(ekey.getRecipientsCertificate() != null) 
						System.out.print("\n\t\tCERT: " + ekey.getRecipientsCertificate().getSubjectDN().getName());
					System.out.println();
				}
				// encryption properties
				System.out.print("\tEncryptionProperties");
				if(m_cdoc.getEncryptionPropertiesId() != null)
					System.out.print(" Id: " + m_cdoc.getEncryptionPropertiesId());
				System.out.println();
				for(int i = 0; i < m_cdoc.getNumProperties(); i++) {
					EncryptionProperty eprop = m_cdoc.getProperty(i);
					System.out.print("\t\tEncryptionProperty");
					if(eprop != null) {
					if(eprop.getId() != null)
						System.out.print(" Id: " + eprop.getId());
					if(eprop.getTarget() != null)
						System.out.print(" Target: " + eprop.getTarget());
					if(eprop.getName() != null)
						System.out.print(" Name: " + eprop.getName());
					if(eprop.getContent() != null)
						System.out.print(" --> " + eprop.getContent());
					}
					System.out.println();
				}
			} else
				return false; // nothing read in to display
		}			
		return true; // nothing to do?
	}

	/**
	 * Checks for commands related to
	 * displaying encrypted documents
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runValidateEncryptedDataCmds(String[] args)
	{
		boolean bFound = false;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-cdoc-validate")) {
				bFound = true;
				break;
			}
		}
		if(bFound) {
			if(m_cdoc != null) {
				System.out.println("Validating Encrypted document: ");
				// display data files
				ArrayList errs = m_cdoc.validate();
				if(errs.size() == 0)
					System.out.println(" --> OK");
				else
					System.out.println(" --> ERROR");
				for(int j = 0; j < errs.size(); j++) 
					System.out.println("\t\t" + (DigiDocException)errs.get(j)); 
				
			} else
				return false; // nothing read in to display
		}			
		return true; // nothing to do?
	}
	
	/**
	 * Checks for commands related to
	 * checking certificates
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runCheckCertCmds(String[] args)
	{
		boolean bOk = true;
		String inFile = null;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-check-cert")) {
				if(i < args.length - 1) {
					inFile = args[i+1];
					break;
				}
				else
					bOk = false;
			}
		}
		if(bOk && inFile != null) {
			System.out.println("Reading certificate file: " + inFile);
			try {
				NotaryFactory notFac = ConfigManager.
						instance().getNotaryFactory();
				X509Certificate cert = SignedDoc.readCertificate(new File(inFile));
				notFac.checkCertificate(cert);
				System.out.println("Certificate is OK");
			    bOk = true;
			} catch(Exception ex) {
				bOk = false;
				System.err.println("ERROR: checking certificate: " + inFile + " - " + ex);
				ex.printStackTrace(System.err);
			}
		}			
		return bOk;
	}
	
	private void printErrsAndWarnings(SignedDoc sdoc, ArrayList lerrs, boolean bLibErrs)
	{
		for(int i = 0; i < lerrs.size(); i++) {
			DigiDocException err = (DigiDocException)lerrs.get(i);
			if(!isWarning(m_sdoc, err)) {
				System.err.println("ERROR: " + err.getCode() + " - " + err.getMessage());
			}
		}
		for(int i = 0; i < lerrs.size(); i++) {
			DigiDocException err = (DigiDocException)lerrs.get(i);
			if(isWarning(m_sdoc, err)) {
				System.err.println("WARNING: " + err.getCode() + " - " + err.getMessage());
			}
		}
		if(bLibErrs) {
			for(int i = 0; i < lerrs.size(); i++) {
				DigiDocException err = (DigiDocException)lerrs.get(i);
				if(err.getCode() != DigiDocException.ERR_TEST_SIGNATURE)
				System.err.println("LIBRARY-ERROR: " + err.getCode() + " - " + err.getMessage());
			}
		}
	}
	
	/**
	 * Checks for commands related to
	 * reading signed documents
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runReadSignedDocCmds(String[] args, ArrayList lerr)
	{
		boolean bOk = true, bStream = false, bOStream = false, bLibErrs = false, bFatal=false;
		String inFile = null;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
		  if(args[i].equals("-libraryerrors")) 
			bLibErrs = true;
		}
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-ddoc-in") || args[i].equals("-ddoc-in-stream") || args[i].equals("-ddoc-in-ostream")) {
				if(args[i].equals("-ddoc-in-stream"))
					bStream = true;
				if(args[i].equals("-ddoc-in-ostream"))
					bOStream = true;
				if(i < args.length - 1) {
					sFilIn = inFile = args[i+1];
					break;
				}
				else
					bOk = false;
			}
		}
		if(bOk && inFile != null) {
			System.out.println("Reading digidoc file: " + inFile);
			DigiDocFactory digFac = null;
			try {
				if(bOStream) {
					ObjectInputStream ois = new ObjectInputStream(new FileInputStream(inFile));
					m_sdoc = (SignedDoc)ois.readObject();
					bOk = true;
					ois.close();
				} else if(bStream) {
					SAXDigiDocFactory saxFac = new SAXDigiDocFactory();
					m_sdoc = saxFac.readSignedDocFromStreamOfType(new FileInputStream(inFile), saxFac.isBdocExtension(inFile), lerr);
					bOk = !hasNonWarningErrs(m_sdoc, lerr);
					printErrsAndWarnings(m_sdoc, lerr, bLibErrs);
				} else {
					digFac = ConfigManager.instance().getDigiDocFactory();
					m_sdoc = digFac.readSignedDocOfType(inFile, digFac.isBdocExtension(inFile), lerr);
					bOk = !hasNonWarningErrs(m_sdoc, lerr);
					printErrsAndWarnings(m_sdoc, lerr, bLibErrs);
				}
				if(m_sdoc != null && m_sdoc.getFormat() != null && m_sdoc.getVersion() != null &&
				   (m_sdoc.getFormat().equals(SignedDoc.FORMAT_SK_XML) ||
				   (m_sdoc.getFormat().equals(SignedDoc.FORMAT_DIGIDOC_XML) &&
				   (m_sdoc.getVersion().equals(SignedDoc.VERSION_1_1) || m_sdoc.getVersion().equals(SignedDoc.VERSION_1_2))))) {
					printErrsAndWarnings(m_sdoc, lerr, bLibErrs);
				}
							
			} catch(Exception ex) {
				boolean bHasSigValCmd = false;
				if(ex instanceof DigiDocException) {
					DigiDocException dex = (DigiDocException)ex;
					if(dex.getCode() == DigiDocException.ERR_SIGNATURE_VALUE_ID) {
						for(int i = 0; (args != null) && (i < args.length); i++) {
							if(args[i].equals("-ddoc-add-sign-value")) {
								bHasSigValCmd = true;
								break;
							}
						}
					}
				}
				if(!bHasSigValCmd) {
				  bOk = false;
				  System.err.println("ERROR: reading digidoc: " + inFile + " - " + ex);
				  ex.printStackTrace(System.err);
				} else {
					System.err.println("Signature with no signature value read in input");
					bOk = true;
				}
			}
		}			
		return bOk;
	}

	/**
	 * Checks for commands related to
	 * reading encrypted documents
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runReadEncryptedDataCmds(String[] args)
	{
		boolean bOk = true;
		String inFile = null;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-cdoc-in")) {
				if(i < args.length - 2) {
					sFilIn = inFile = args[i+1];
					break;
				}
				else
					bOk = false;
			}
		}
		if(bOk && inFile != null) {
			System.out.println("Reading encrypted file: " + inFile);
			try {
				EncryptedDataParser dencFac =  ConfigManager.
					instance().getEncryptedDataParser();
				m_cdoc = dencFac.readEncryptedData(inFile);
				bOk = true;
			} catch(Exception ex) {
				bOk = false;
				System.err.println("ERROR: reading encrypted file: " + inFile + " - " + ex);
				ex.printStackTrace(System.err);
			}
		}			
		return bOk;
	}

	/**
	 * Checks for commands related to
	 * reading signed documents
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runEncryptEncryptedDataCmds(String[] args)
	{
		boolean bOk = true, bFound = false;
		String inFile = null, outFile = null;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-cdoc-encrypt")) {
				bFound = true;
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					inFile = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					outFile = args[i+1];
					i++;
				}
			}
		}
		if(bFound) {
			if(outFile != null && inFile != null) {
				System.out.println("Encrypting file: " + inFile + " to: " + outFile);
				bOk = m_cdoc.encryptFileData(inFile, outFile);
			} else {
				bOk = false;
				System.err.println("Missing input file or output file of the -cdoc-encrypt command");
			}
		}	
		return bOk;
	}
	
	/**
	 * Checks for commands related to
	 * reading signed documents
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runEncryptEncryptedDataSKCmds(String[] args)
	{
		boolean bOk = true, bFound = false;
		String inFile = null, outFile = null;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-cdoc-encrypt-sk")) {
				bFound = true;
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					inFile = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					outFile = args[i+1];
					i++;
				}
			}
		}
		if(bFound) {
			if(outFile != null && inFile != null) {
				System.out.println("Encrypting file: " + inFile + " to: " + outFile);
				try {
					File fIn = new File(inFile);
					// create ddoc intermediate file
					m_sdoc = new SignedDoc(SignedDoc.FORMAT_DIGIDOC_XML, SignedDoc.VERSION_1_3);
					DataFile df = m_sdoc.addDataFile(new File(inFile), SignedDoc.xmlns_digidoc13, DataFile.CONTENT_EMBEDDED_BASE64);
					byte[] data = SignedDoc.readFile(new File(inFile));
					df.setBase64Body(data);
					byte[] inData = m_sdoc.toXML().getBytes("UTF-8");
					// TODO: check cdoc existencs
					m_cdoc.setData(inData);
					m_cdoc.setDataStatus(EncryptedData.DENC_DATA_STATUS_UNENCRYPTED_AND_NOT_COMPRESSED);
					m_cdoc.addProperty(EncryptedData.ENCPROP_FILENAME, inFile + ".ddoc");
					m_cdoc.setMimeType(EncryptedData.DENC_ENCDATA_TYPE_DDOC);
					StringBuffer sb = new StringBuffer();
					sb.append(fIn.getName());
					sb.append("|");
					sb.append(new Long(fIn.length()).toString());
					sb.append("|");
					sb.append("application/unknown|");
					sb.append(df.getId());
					m_cdoc.addProperty(EncryptedData.ENCPROP_ORIG_FILE, sb.toString());
					m_cdoc.addProperty(EncryptedData.ENCPROP_ORIG_SIZE, new Long(data.length).toString());
					m_cdoc.encrypt(EncryptedData.DENC_COMPRESS_NEVER); 
					FileOutputStream fos = new FileOutputStream(outFile);
					fos.write(m_cdoc.toXML());
					fos.close();
					bOk = true;
				} catch(Exception ex) {
					bOk = false;
					System.err.println("ERROR: encrypting file: " + inFile + " - " + ex);
					ex.printStackTrace(System.err);
				}
			} else {
				bOk = false;
				System.err.println("Missing input file or output file of the -cdoc-encrypt command");
			}
		}	
		return bOk;
	}
	
	/**
	 * Checks for commands related to
	 * decrypting encrypted documents
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runDecryptEncryptedDataCmds(String[] args)
	{
		boolean bOk = true, bFound = false, bExtract = false;
		String pin = null, outFile = null, keystoreFile = null;
		String sImpl = SignatureFactory.SIGFAC_TYPE_PKCS11;
		
		int nSlot = 0;
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-cdoc-decrypt") || args[i].equals("-cdoc-decrypt-sk")) {
				if(args[i].equals("-cdoc-decrypt-sk"))
					bExtract = true;
				bFound = true;
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					pin = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					outFile = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					nSlot = Integer.parseInt(args[i+1]);
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					sImpl = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					keystoreFile = args[i+1];
					i++;
				}
			}
			
		}
		if(bFound) {
			if(pin != null && outFile != null) {
				System.out.println("Decrypting to: " + outFile);
				try {
					// TODO: check cdoc existencs
					ConfigManager cfg = ConfigManager.instance();
					SignatureFactory sigFac = cfg.getSignatureFactoryOfType(sImpl);
					if(sigFac == null) {
						System.err.println("No signature factory of type: " + sImpl);
						return false;
					} else {
						if(sigFac.getType().equals(SignatureFactory.SIGFAC_TYPE_PKCS12)) {
						  Pkcs12SignatureFactory p12sfac = (Pkcs12SignatureFactory)sigFac;
						  bOk = p12sfac.load(keystoreFile, SignatureFactory.SIGFAC_TYPE_PKCS12, pin);
						}
					}
					if(!bOk) {
						System.out.println("Failed to load signature token!");
						return bOk;
					}
					X509Certificate cert = sigFac.getAuthCertificate(nSlot, pin);
					int nIdx = m_cdoc.getRecvIndex(cert);
					if(nIdx < 0) {
						System.err.println("No decryption key found on smartcard to decrypt this file!");
						return false;
					}
					m_cdoc.decrypt(sImpl, keystoreFile, nIdx, nSlot, pin);
					//m_cdoc.decrypt(0, 0, pin);
					if(bExtract) {
						//System.out.println("extracting D0");
						//System.out.println("Writing ddoc to: " + outFile);
						FileOutputStream fos = new FileOutputStream(outFile);
						fos.write(m_cdoc.getData());
						fos.close();
						DigiDocFactory digFac = ConfigManager.instance().getDigiDocFactory();
						m_sdoc = digFac.readSignedDoc(outFile);
						DataFile df = m_sdoc.getDataFile(0);
						//System.out.println("Writing extracted data to: " + outFile);
						fos = new FileOutputStream(outFile);
		                InputStream is = df.getBodyAsStream();
		                if(is == null) {
		                	System.err.println("DataFile has no data!");
		                	return false;
		                }
		                byte[] data = new byte[4096];
		                int n = 0, m = 0;
		                while((n = is.read(data)) > 0) {
		                	fos.write(data, 0, n);
		                	m += n;
		                }
		                fos.close();
		                is.close();
		                		
					} else {
					FileOutputStream fos = new FileOutputStream(outFile);
					fos.write(m_cdoc.getData());
					fos.close();
					}
					bOk = true;
				} catch(Exception ex) {
					bOk = false;
					System.err.println("ERROR: decrypting file: " + ex);
					ex.printStackTrace(System.err);
				}
			} else {
				bOk = false;
				System.err.println("Missing pin or output file of the -cdoc-decrypt command");
			}
		}	
		return bOk;
	}
	
	/**
	 * Checks for commands related to
	 * decrypting encrypted documents
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runDecryptEncryptedDataPkcs12Cmds(String[] args)
	{
		boolean bOk = true, bFound = false, bExtract = false;
		String outFile = null, keystoreFile = null, keystorePasswd = null, keystoreType="JKS";
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-cdoc-decrypt-pkcs12") || args[i].equals("-cdoc-decrypt-pkcs12-sk")) {
				if(args[i].equals("-cdoc-decrypt-pkcs12-sk"))
					bExtract = true;
				bFound = true;
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					keystoreFile = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					keystorePasswd = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					keystoreType = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					outFile = args[i+1];
					i++;
				}
			}
		}
		if(bFound) {
			if(keystoreFile != null && keystorePasswd != null && outFile != null) {
				System.out.println("Decrypting to: " + outFile);
				try {
					// TODO: check cdoc existencs
					// check recipient index
					int nKey = -1;
					try {
						System.out.println("Load keystore: " + keystoreFile + " pwd: " + keystorePasswd);
						Pkcs12SignatureFactory p12fac = new Pkcs12SignatureFactory();
						p12fac.init();
						p12fac.load(keystoreFile, keystoreType, keystorePasswd);
						X509Certificate cert = p12fac.getAuthCertificate(0, keystorePasswd);
						System.out.println("Cert: " + ((cert != null) ? cert.getSubjectDN().getName() : "NULL"));
						nKey = m_cdoc.getRecvIndex(cert);
						System.out.println("Using recipient: " + nKey);
					} catch(Exception ex) {
						System.err.println("ERROR: finding cdoc recipient: " + ex);
					}
					m_cdoc.decryptPkcs12(nKey, keystoreFile, keystorePasswd, keystoreType);
					if(bExtract) {
						//System.out.println("extracting D0");
						//System.out.println("Writing ddoc to: " + outFile);
						FileOutputStream fos = new FileOutputStream(outFile);
						fos.write(m_cdoc.getData());
						fos.close();
						DigiDocFactory digFac = ConfigManager.instance().getDigiDocFactory();
						m_sdoc = digFac.readSignedDoc(outFile);
						DataFile df = m_sdoc.getDataFile(0);
						//System.out.println("Writing extracted data to: " + outFile);
						fos = new FileOutputStream(outFile);
		                InputStream is = df.getBodyAsStream();
		                if(is == null) {
		                	System.err.println("DataFile has no data!");
		                	return false;
		                }
		                byte[] data = new byte[4096];
		                int n = 0, m = 0;
		                while((n = is.read(data)) > 0) {
		                	fos.write(data, 0, n);
		                	m += n;
		                }
		                fos.close();
		                is.close();
		                		
					} else {
					FileOutputStream fos = new FileOutputStream(outFile);
					fos.write(m_cdoc.getData());
					fos.close();
					}
					bOk = true;
				} catch(Exception ex) {
					bOk = false;
					System.err.println("ERROR: decrypting file: " + ex);
					ex.printStackTrace(System.err);
				}
			} else {
				bOk = false;
				System.err.println("Missing keystore file, password or output file of the -cdoc-decrypt-pkcs12 command");
			}
		}	
		return bOk;
	}

	/**
	 * Checks for commands related to
	 * decrypting encrypted documents
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runDecryptEncryptedDataPkcs12StreamCmds(String[] args)
	{
		boolean bOk = true, bFound = false, bExtract = false;
		String inFile = null, outFile = null, keystoreFile = null, keystorePasswd = null, keystoreType="JKS", recipient = null;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-cdoc-decrypt-pkcs12-stream") || args[i].equals("-cdoc-decrypt-pkcs12-stream-sk")) {
				if(args[i].equals("-cdoc-decrypt-pkcs12-stream-sk"))
					bExtract = true;
				bFound = true;
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					inFile = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					keystoreFile = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					keystorePasswd = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					keystoreType = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					outFile = args[i+1];
					i++;
				}
				
			}
		}
		if(bFound) {
			if(keystoreFile != null && keystorePasswd != null && outFile != null && inFile != null) {
				try {
					// TODO: check cdoc existencs
					System.out.println("Decrypting: " + inFile + " to: " + outFile + " recv: " + recipient);
					try {
						FileInputStream fis = new FileInputStream(inFile); 
						FileOutputStream fos = new FileOutputStream(outFile);
						EncryptedStreamParser streamParser = ConfigManager.instance().getEncryptedStreamParser();
						streamParser.decryptStreamUsingTokenType(fis, fos, 0, keystorePasswd, SignatureFactory.SIGFAC_TYPE_PKCS12, keystoreFile);
						fos.close();
						fis.close();
						bOk = true;
					} catch(Exception ex) {
						bOk = false;
						System.err.println("ERROR: decrypting file: " + ex);
						ex.printStackTrace(System.err);
					}
					if(bExtract) {
						DigiDocFactory digFac = ConfigManager.instance().getDigiDocFactory();
						m_sdoc = digFac.readSignedDoc(outFile);
						DataFile df = m_sdoc.getDataFile(0);
						//System.out.println("Writing extracted data to: " + outFile);
						FileOutputStream fos = new FileOutputStream(outFile);
		                InputStream is = df.getBodyAsStream();
		                if(is == null) {
		                	System.err.println("DataFile has no data!");
		                	return false;
		                }
		                byte[] data = new byte[4096];
		                int n = 0, m = 0;
		                while((n = is.read(data)) > 0) {
		                	fos.write(data, 0, n);
		                	m += n;
		                }
		                fos.close();
		                is.close();
		                		
					} 
					bOk = true;
				} catch(Exception ex) {
					bOk = false;
					System.err.println("ERROR: decrypting file: " + ex);
					ex.printStackTrace(System.err);
				}
			} else {
				bOk = false;
				System.err.println("Missing keystore file, password or output file of the -cdoc-decrypt-pkcs12-stream command");
			}
		}	
		return bOk;
	}

	/**
	 * Checks for commands related to
	 * decrypting large encrypted documents
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runDecryptEncryptedStreamCmds(String[] args)
	{
		boolean bOk = true, bFound = false;
		String pin = null, outFile = null, inFile = null;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-cdoc-decrypt-stream")) {
				bFound = true;
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					inFile = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					pin = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					outFile = args[i+1];
					i++;
				}
			}
		}
		if(bFound) {
			if(pin != null && outFile != null && inFile != null) {
				System.out.println("Decrypting: " + inFile + " to: " + outFile);
				try {
					FileInputStream fis = new FileInputStream(inFile); 
					FileOutputStream fos = new FileOutputStream(outFile);
					EncryptedStreamParser streamParser = ConfigManager.instance().getEncryptedStreamParser();
					streamParser.decryptStreamUsingTokenType(fis, fos, 0, pin, SignatureFactory.SIGFAC_TYPE_PKCS11, null);
					fos.close();
					fis.close();
					bOk = true;
				} catch(Exception ex) {
					bOk = false;
					System.err.println("ERROR: decrypting file: " + ex);
					ex.printStackTrace(System.err);
				}
			} else {
				bOk = false;
				System.err.println("Missing input file, recipient name, pin or output file of the -cdoc-decrypt-stream command");
			}
		}	
		return bOk;
	}
	
	/**
	 * Checks for commands related to
	 * decrypting large encrypted documents
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runDecryptEncryptedStreamRecvCmds(String[] args)
	{
		boolean bOk = true, bFound = false;
		String pin = null, outFile = null, inFile = null, recv = null;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-cdoc-decrypt-stream-recv")) {
				bFound = true;
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					inFile = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					pin = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					outFile = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					recv = args[i+1];
					i++;
				}
			}
		}
		if(bFound) {
			if(pin != null && outFile != null && inFile != null && recv != null) {
				System.out.println("Decrypting: " + inFile + " to: " + outFile);
				try {
					FileInputStream fis = new FileInputStream(inFile); 
					FileOutputStream fos = new FileOutputStream(outFile);
					EncryptedStreamParser streamParser = ConfigManager.instance().getEncryptedStreamParser();
					//streamParser.decryptStreamUsingTokenType(fis, fos, 0, pin, SignatureFactory.SIGFAC_TYPE_PKCS11, null);
					streamParser.decryptStreamUsingRecipientName(fis, fos, 0, pin, recv);
					fos.close();
					fis.close();
					bOk = true;
				} catch(Exception ex) {
					bOk = false;
					System.err.println("ERROR: decrypting file: " + ex);
					ex.printStackTrace(System.err);
				}
			} else {
				bOk = false;
				System.err.println("Missing input file, recipient name, pin or output file of the -cdoc-decrypt-stream command");
			}
		}	
		return bOk;
	}

	/**
	 * Checks for commands related to
	 * decrypting large encrypted documents
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runDecryptEncryptedStreamSlotAndLabelCmds(String[] args)
	{
		boolean bOk = true, bFound = false;
		String pin = null, outFile = null, inFile = null, slot = null, label = null;
		int nSlot = 0;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-cdoc-decrypt-stream-slot-label")) {
				bFound = true;
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					inFile = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					pin = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					outFile = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					slot = args[i+1];
					if(slot != null && slot.length() > 0)
						nSlot = Integer.parseInt(slot);
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					label = args[i+1];
					i++;
				}
			}
		}
		if(bFound) {
			if(pin != null && outFile != null && inFile != null && label != null && nSlot > 0) {
				System.out.println("Decrypting: " + inFile + " to: " + outFile);
				try {
					FileInputStream fis = new FileInputStream(inFile); 
					FileOutputStream fos = new FileOutputStream(outFile);
					EncryptedStreamParser streamParser = ConfigManager.instance().getEncryptedStreamParser();
					streamParser.decryptStreamUsingRecipientSlotIdAndTokenLabel(fis, fos, nSlot, label, pin);
					fos.close();
					fis.close();
					bOk = true;
				} catch(Exception ex) {
					bOk = false;
					System.err.println("ERROR: decrypting file: " + ex);
					ex.printStackTrace(System.err);
				}
			} else {
				bOk = false;
				System.err.println("Missing input file, recipient name, pin or output file of the -cdoc-decrypt-stream command");
			}
		}	
		return bOk;
	}

	/**
	 * Checks for commands related to
	 * encrypting big files
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runEncryptStreamCmds(String[] args)
	{
		boolean bOk = true, bFound = false;
		String inFile = null, outFile = null;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-cdoc-encrypt-stream")) {
				bFound = true;
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					inFile = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					outFile = args[i+1];
					i++;
				}
			}
		}
		if(bFound) {
			if(outFile != null && inFile != null) {
				System.out.println("Encrypting file: " + inFile + " to: " + outFile);
				try {
					// TODO: check cdoc existencs
					File fin = new File(inFile);
					m_cdoc.addProperty(EncryptedData.ENCPROP_FILENAME, inFile);
					if(inFile.endsWith(".bdoc") || inFile.endsWith(".asice"))
						m_cdoc.setMimeType(SignedDoc.MIMET_FILE_CONTENT_20);
					m_cdoc.encryptStream(new FileInputStream(inFile), new FileOutputStream(outFile), EncryptedData.DENC_COMPRESS_NEVER);
					bOk = true;
				} catch(Exception ex) {
					bOk = false;
					System.err.println("ERROR: encrypting file: " + inFile + " - " + ex);
					ex.printStackTrace(System.err);
				}
			} else {
				bOk = false;
				System.err.println("Missing input file or output file of the -cdoc-encrypt-stream command");
			}
		}	
		return bOk;
	}
		
	/**
	 * Checks for commands related to
	 * adding recipients (EncryptedKey -s) encrypted documents
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runAddRecipientsCmds(String[] args)
	{
		boolean bOk = true;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-cdoc-recipient")) {
				String certFile = null;
				String recipient = null;
				String keyName = null;
				String carriedKeyName = null;
				String sId = null;
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					certFile = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					recipient = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					keyName = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					carriedKeyName = args[i+1];
					i++;
				}
				if(certFile != null) {
					try {
						if(m_cdoc == null) {
							System.out.println("Creating encrypted document");
							m_cdoc = new EncryptedData(null, null, null, EncryptedData.DENC_XMLNS_XMLENC, EncryptedData.DENC_ENC_METHOD_AES128);
						}
						System.out.println("Adding recipient: " + certFile + ", " + recipient + ", " + keyName + ", " + carriedKeyName);
						X509Certificate recvCert = SignedDoc.readCertificate(new File(certFile));
						if(recvCert != null && recipient == null)
							recipient = SignedDoc.getCommonName(recvCert.getSubjectDN().getName());
						//System.out.println("Recipient: " + recipient);
						if(sId == null) {
							int n = m_cdoc.getNumKeys() + 1;
							sId = "ID" + n;
						}
						EncryptedKey ekey = new EncryptedKey(sId, recipient, EncryptedData.DENC_ENC_METHOD_RSA1_5, keyName, carriedKeyName, recvCert);
						m_cdoc.addEncryptedKey(ekey);
					} catch(Exception ex) {
						bOk = false;
						System.err.println("ERROR: adding EncryptedKey: " + ex);
						ex.printStackTrace(System.err);
					}
				} else {
					bOk = false;
					System.err.println("Missing certificate file of -cdoc-recipient command");
				}
			}
		}
		return bOk; // nothing to do?
	}

	/**
	 * Checks for configuration commands
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runHelpCmds(String[] args)
	{
		boolean bOk = false;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-?") || args[i].equals("-help")) {
				return true;
			}
		}
		if(args.length == 0)  {
			System.out.println("args: " + args.length);
			return true;
		}
		return false;
	}
	
	/**
	 * Checks for configuration commands
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runConfigCmds(String[] args)
	{
		boolean bOk = true;
		String cfgFile = "jar://jdigidoc.cfg"; // default value
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-config")) {
				if(i < args.length - 2) 
					cfgFile = args[i+1];
				else
					bOk = false;
			}
		}
		if(bOk) {
			System.out.println("Reading config file: " + cfgFile);
			bOk = ConfigManager.init(cfgFile);
		}			
		return bOk;
	}
	
	/**
	 * command for testing ddoc file for correct start and end tags
	 * Checks if rubbish bytes are at the end
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runCheckValidDdocCmds(String[] args)
	{
		boolean bOk = true;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-cdoc-test")) {
				String testFile = null;
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					testFile = args[i+1];
					i++;
				}
				
				if(testFile != null) {
					try {
						ByteArrayOutputStream bos = new ByteArrayOutputStream();
						FileInputStream fis = new FileInputStream(testFile);
						byte[] data = new byte[1024];
						int n = 0;
						while((n = fis.read(data)) > 0)
							bos.write(data, 0, n);
						fis.close();
						data = bos.toByteArray();
						bos = null;
						// now test it
						String s = new String(data);
						if(!s.startsWith("<?xml") && !s.startsWith("<SignedDoc")) {
							System.err.println("Invalid ddoc: " + testFile + " - bad file begin");
							bOk = false;
						} else if(!s.endsWith("</SignedDoc>")) {
							System.err.println("Invalid ddoc: " + testFile + " - bad file end");
							bOk = false;
						} else {
							System.err.println("Good ddoc: " + testFile);
							bOk = true;
						}
					} catch(Exception ex) {
						System.err.println("ERROR: testing ddoc: " + testFile + " - " + ex);
						ex.printStackTrace(System.err);
					}
				} else {
					bOk = false;
					System.err.println("Missing certificate file of -cdoc-recipient command");
				}
			}
		}
		return bOk; // nothing to do?
	}
	
	private String composeHttpFrom()
	{
		// set HTTP_FROM to some value
		String sFrom = null;
		try {
			NetworkInterface ni = null;
			Enumeration eNi = NetworkInterface.getNetworkInterfaces();
			if(eNi != null && eNi.hasMoreElements())
				ni = (NetworkInterface)eNi.nextElement();
			if(ni != null) {
				InetAddress ia = null;
				Enumeration eA = ni.getInetAddresses();
				if(eA != null && eA.hasMoreElements())
					ia = (InetAddress)eA.nextElement();
				if(ia != null)
					sFrom = ia.getHostAddress();
				System.err.println("FROM: " + sFrom);
			}
		} catch(Exception ex2) {
			System.err.println("ERROR: finding ip-adr: " + ex2);
		}
		return sFrom;
	}
	
	
	/**
	 * Checks for commands related to signing signed documents.
	 * Uses slot id and token label to identify token to be used for signing.
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runSignSignedDocSlotLabelCmds(String[] args)
	{
		boolean bOk = true;
		String sImpl = null;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-ddoc-sign-slot-label")) {
				String pin = null;
				String rollReso = null;
				String country = null;
				String city = null;
				String state = null;
				String zip = null;
				String profile = null;
				String slot = null;
				int nSlot = 0;
				String label = null;
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					slot = args[i+1];
					if(slot != null && slot.length() > 0)
						nSlot = Integer.parseInt(slot);
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					label = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					pin = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					rollReso = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					country = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					state = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					city = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					zip = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					profile = args[i+1];
					i++;
				}
				
				if(pin != null) {
					try {
						if(m_sdoc == null) {
							System.err.println("No signed document to sign. Use -ddoc-in or -ddoc-new commands!");
							return false;
						}
						// roll/resolutsioon
						String[] roles = null;
						if(rollReso != null && rollReso.trim().length() > 0) {
							roles = new String[1];
							roles[0] = rollReso;
						}
						// address
						SignatureProductionPlace adr = null;
						if(country != null || state != null || city != null || zip != null)
							adr = new SignatureProductionPlace(city, state, country, zip);
						System.out.println("Signing digidoc");
						ConfigManager cfg = ConfigManager.instance();
						System.err.println("Signing of type: " + sImpl);
						PKCS11SignatureFactory sigFac = (PKCS11SignatureFactory)cfg.
								getSignatureFactoryOfType(SignatureFactory.SIGFAC_TYPE_PKCS11);
						if(sigFac == null) {
							System.err.println("No PKCS11 signature factory");
							return false;
						} 
						TokenKeyInfo tki = sigFac.getTokenWithSlotIdAndLabel(nSlot, label);
						if(tki == null) {
							System.err.println("No token with slot: " + nSlot + " and label: " + label);
							return false;
						}
						X509Certificate cert = sigFac.getCertificateWithSlotIdAndLabel(nSlot, label);
						System.out.println("Prepare signature, cert: " + ((cert != null) ? "OK" : "NULL") + " status: " + bOk);
						Signature sig = m_sdoc.prepareSignature(cert, roles, adr);
						if(profile == null)
							profile = ConfigManager.instance().getStringProperty("DIGIDOC_DEFAULT_PROFILE", "TM");
						if(profile != null)
							sig.setProfile(profile);
						
						byte[] sidigest = sig.calculateSignedInfoDigest();
						byte[] sigval = sigFac.sign(sidigest, nSlot, label, pin, sig);
						// finalize signature up to default profile
						System.out.println("Finalize signature: " + sig.getId() + " profile: " + profile + " sig-len: " + ((sigval != null) ? sigval.length : 0));
						sig.setSignatureValue(sigval);
						// set HTTP_FROM to some value
						sig.setHttpFrom(composeHttpFrom());
						sig.getConfirmation();
						
					} catch(Exception ex) {
						bOk = false;
						System.err.println("ERROR: signing: " + ex);
						ex.printStackTrace(System.err);
					}
				} else {
					bOk = false;
					System.err.println("Missing pin of -ddoc-sign-slot-label command");
				}
			}
		}
		return bOk; // nothing to do?
	}
	

	
	/**
	 * command for listing all useable keys.
	 * This command currently uses only PKCS11 interface
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runListKeysCmds(String[] args)
	{
		boolean bOk = true;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-ddoc-list-keys")) {
				try {
					PKCS11SignatureFactory sigFac = (PKCS11SignatureFactory)ConfigManager.
							instance().getSignatureFactoryOfType(SignatureFactory.SIGFAC_TYPE_PKCS11);
					if(sigFac == null) {
						System.err.println("PKCS11 interface not available!");
						return false;
					}
					TokenKeyInfo[] ltok = sigFac.getTokenKeys();
					for(int j = 0; (ltok != null) && (j < ltok.length); j++) {
						TokenKeyInfo tok = ltok[j];
						System.out.println("Token: " + tok.getNr() + " slot: " + tok.getSlot() +
								" label " + tok.getLabel() +
								" id: " + tok.getIdHex() + " cert: " + tok.getCertSerial() +
								" CN: " + tok.getCertName() + " signing: " + tok.isSignatureKey() + 
								" encryption: " + tok.isEncryptKey());
					}
					bOk = true;
				} catch(Exception ex) {
					System.err.println("ERROR: listing keys: " + ex);
					ex.printStackTrace(System.err);
				}
			}
		}
		return bOk; // nothing to do?
	}

	/**
	 * run-loop for jdigidoc. Evaluates the command line arguments
	 * and executes the commands
	 * @param args command line arguments
	 */
	public boolean run(String[] args)
	{
		boolean bOk = true, b = false, bContinue = true, bHelp = false;
		ArrayList lerr = new ArrayList();
		
		bHelp = runHelpCmds(args);
		// check config file
		bOk = runConfigCmds(args);
		// register provider
		if(bOk)
			ConfigManager.addProvider();
		// checking certificates 
		if(bOk)
			bOk = runCheckCertCmds(args);
		// list keys
		if(bOk)
			bOk = runListKeysCmds(args);
		// reading of digidoc files
		if(bOk)  {
			bOk = runReadSignedDocCmds(args, lerr);
			bContinue = !SignedDoc.hasFatalErrs(lerr);
		}
		// creating digidocs
		if(bOk)
			bOk = runNewSignedDocCmds(args);
		// adding data files
		if(bOk)
			bOk = runAddSignedDocCmds(args);
		if(bOk)
			bOk = runAddMemSignedDocCmds(args);
		// signing digidoc-s
		if(bOk)
			bOk = runSignSignedDocCmds(args);		
		// sign using pkcs11 by key id
		if(bOk)
			bOk = runSignSignedDocSlotLabelCmds(args);
		// calc-sign
		if(bOk)
			bOk = runCalcSignCmds(args);
		// add-sign-value
		if(bOk)
			bOk = runAddSignValueCmds(args);
		
		// notarizing digidoc-s
		if(bOk)
			bOk = runNotarizeSignedDocCmds(args);
		if(bOk)
			bOk = runRmvSigCmds(args);
		if(bOk)
			bOk = runRmvDfCmds(args);
		// writing digidoc's
		if(bOk)
			bOk = runWriteSignedDocCmds(args);
		// validate signed doc
		if(bContinue) {
			b = runValidateSignedDocCmds(args);
			if(!b) bOk = false;
		}
		if(bOk)
			bOk = runExtractDataFileCmds(args);
		
		// read encrypted files
		if(bOk)
			bOk = runReadEncryptedDataCmds(args);
		// add recipients
		if(bOk)
			bOk = runAddRecipientsCmds(args);
		// encrypt data
		if(bOk)
			bOk = runEncryptEncryptedDataCmds(args);
		if(bOk) // SK specific cdoc containing ddoc internal container
			bOk = runEncryptEncryptedDataSKCmds(args);
		// encrypt data
		if(bOk)
			bOk = runEncryptStreamCmds(args);
		// decrypt data
		if(bOk)
			bOk = runDecryptEncryptedDataCmds(args);
		// decrypt using pkcs12 factory (also jks keystores)
		if(bOk)
			bOk = runDecryptEncryptedDataPkcs12Cmds(args);
		// decrypt pkcs12 stream
		if(bOk)
			bOk = runDecryptEncryptedDataPkcs12StreamCmds(args);
		// decrypt data
		if(bOk)
			bOk = runDecryptEncryptedStreamCmds(args);
		if(bOk)
			bOk = runDecryptEncryptedStreamRecvCmds(args);
		if(bOk)
			bOk = runDecryptEncryptedStreamSlotAndLabelCmds(args);
		// display encrypted doc
		if(bOk)
			bOk = runListEncryptedDataCmds(args);
		// validate encrypted doc
		if(bOk)
			bOk = runValidateEncryptedDataCmds(args);
		// test cdoc commands
		if(bOk)
			bOk = runCheckValidDdocCmds(args);
		
		if(bHelp) {
			System.err.println("USAGE: ee.sk.test.jdigidoc [commands]");
			System.err.println("\t-? or -help - displays this help screen");
			System.err.println("\t-config <configuration-file> [default: jar://jdigidoc.cfg]");
			System.err.println("\t-check-cert <certficate-file-in-pem-format>");
			
			System.err.println("\t-ddoc-in <input-digidoc-file>");
			System.err.println("\t-ddoc-in-stream <input-digidoc-file>");
			System.err.println("\t-ddoc-in-ostream <input-digidoc-file>");
			System.err.println("\t-ddoc-new [format] [version]");
			System.err.println("\t-ddoc-add <input-file> <mime-typ> [content-type]");
			System.err.println("\t-ddoc-add-mem <input-file> <mime-typ> [content-type]");
			System.err.println("\t-ddoc-sign <pin-code> [roll/resolutsioon] [country] [state] [city] [zip] [slot(0)] [profile] [driver(PKCS11)] [keystoreFile]");
			System.err.println("\t-ddoc-out <ouput-file>");			
			System.err.println("\t-ddoc-out-stream <ouput-file>");			
			System.err.println("\t-ddoc-out-ostream <ouput-file>");			
			System.err.println("\t-ddoc-validate");
			System.err.println("\t-ddoc-extract <data-file-id> <output-file>");
			System.err.println("\t-ddoc-rm-sig <signature-id>");
			System.err.println("\t-ddoc-rm-df <data-file-id>");

			System.err.println("\t-ddoc-list-keys");
			System.err.println("\t-ddoc-sign-slot-label <slot-id> <label> <pin-code> [manifest] [country] [state] [city] [zip] [profile]");
			System.err.println("\t-cdoc-decrypt-stream-slot-label <input-file> <pin> <output-file> <slot> <label>");

			System.err.println("\t-ddoc-calc-sign <cert-file> [roll/resolutsioon] [country] [state] [city] [zip]] [profile]");
			System.err.println("\t-ddoc-add-sign-value <sign-val-file> <sign-id>");

			System.err.println("\t-cdoc-in <input-encrypted-file>");
			System.err.println("\t-cdoc-list");
			System.err.println("\t-cdoc-validate");
			System.err.println("\t-cdoc-recipient <certificate-file> [recipient] [KeyName] [CarriedKeyName]");
			System.err.println("\t-cdoc-encrypt <input-file> <output-file>");
			System.err.println("\t-cdoc-encrypt-sk <input-file> <output-file>");
			System.err.println("\t-cdoc-encrypt-stream <input-file> <output-file>");
			System.err.println("\t-cdoc-decrypt <pin> <output-file> [slot(0)]");
			System.err.println("\t-cdoc-decrypt-sk <pin> <output-file> [slot(0)]");
			System.err.println("\t-cdoc-decrypt-stream <input-file> <pin> <output-file>");
			System.err.println("\t-cdoc-decrypt-stream-recv <input-file> <pin> <output-file> <recipient>");
			System.err.println("\t-cdoc-test <input-file>");
			System.err.println("\t-cdoc-decrypt-pkcs12 <keystore-file> <keystore-passwd> <keystore-type> <output-file>");
			System.err.println("\t-cdoc-decrypt-pkcs12-sk <keystore-file> <keystore-passwd> <keystore-type> <output-file>");
			System.err.println("\t-cdoc-decrypt-pkcs12-stream <input-file> <keystore-file> <keystore-passwd> <keystore-type> <output-file>");
			System.err.println("\t-cdoc-decrypt-pkcs12-stream-sk <input-file> <keystore-file> <keystore-passwd> <keystore-type> <output-file>");
			System.err.println("\t-libraryerrors");
		}
		
		// cleanup data-file cache
		if(m_sdoc != null)
			m_sdoc.cleanupDfCache();
		return bOk;
	}

	/**
	 * jdigidoc's main routine.
	 * @param args command line arguments
	 */
	public static void main(String[] args) 
	{
		Date ds, de;
		jdigidoc prog;
		// print program name & version
		System.out.println(SignedDoc.LIB_NAME + " - " + SignedDoc.LIB_VERSION);
		ds = new Date();
		prog = new jdigidoc();
		boolean bOk = prog.run(args);
		de = new Date();
		System.out.println(SignedDoc.LIB_NAME + " end, time: " + ((de.getTime() - ds.getTime()) / 1000) + " sec result: " + (bOk ? "success" : "failure"));
		
	}
}
