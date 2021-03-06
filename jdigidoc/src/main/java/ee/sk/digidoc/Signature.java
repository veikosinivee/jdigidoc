/*
 * Signature.java
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

package ee.sk.digidoc;
import java.io.Serializable;
import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;

import ee.sk.digidoc.factory.NotaryFactory;
import ee.sk.digidoc.factory.TimestampFactory;
import ee.sk.digidoc.factory.DigiDocFactory;
import ee.sk.digidoc.factory.DigiDocXmlGenFactory;
import ee.sk.digidoc.factory.DigiDocGenFactory;
import ee.sk.digidoc.factory.DigiDocVerifyFactory;
import ee.sk.utils.ConfigManager;

import java.security.cert.CertStore;
import java.security.cert.X509Certificate;
import ee.sk.utils.ConvertUtils;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import org.apache.log4j.Logger;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampResponse;

/**
 * Models an XML-DSIG/ETSI Signature. A signature
 * can contain references SignedInfo (truly signed data)
 * and signed and unsigned properties.
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class Signature implements Serializable
{
	private static final long serialVersionUID = 1L;
    /** reference to the parent SignedDoc object */
    private SignedDoc m_sigDoc;
    /** signature id */
    private String m_id;
    /** SignedInfo object */
    private SignedInfo m_signedInfo;
    /** SignatureValue object */
    private SignatureValue m_signatureValue;
    /** container comment (bdoc2 lib ver and name) */
    private String m_comment;
    /** KeyInfo object */
    private KeyInfo m_keyInfo;
    /** SignedProperties object */
    private SignedProperties m_sigProp;
    /** QualifyingProperties object */
    private QualifyingProperties m_qualProp;
    /** UnsignedProperties object */
    private UnsignedProperties m_unsigProp;
    /** original bytes read from XML file  */
    private byte[] m_origContent;
	/** CertID elements */
	private ArrayList m_certIds;    
    /** CertValue elements */
	private ArrayList m_certValues;
    /** TimestampInfo elements */
	private ArrayList m_timestamps;
	/** cached list of errors */
	private ArrayList m_errs;
	/** path in bdoc container */
	private String m_path;
	private boolean m_bAltDigMatch;
	/** signature profile - used in bdoc */
	private String m_profile, m_httpFrom;
	private static Logger m_logger = Logger.getLogger(Signature.class);
    
    /** 
     * Creates new Signature 
     */
    public Signature(SignedDoc sigDoc) {
        m_sigDoc = sigDoc;
        m_id = null;
        m_signedInfo = null;
        m_signatureValue = null;
        m_keyInfo = null;
        m_sigProp = null;
        m_unsigProp = null;
        m_origContent = null;
        m_certIds = null;
        m_certValues = null;
        m_timestamps = null;
        m_path = null;
        m_profile = null;
        m_errs = null;
        m_httpFrom = null;
        m_bAltDigMatch = false;
        m_comment = null;
    }
    
    /**
     * Accessor for sigDoc attribute
     * @return value of sigDoc attribute
     */
    public SignedDoc getSignedDoc() {
        return m_sigDoc;
    }
    
    /**
     * Mutator for sigDoc attribute
     * @param sigDoc new value for sigDoc attribute
     */    
    public void setSignedDoc(SignedDoc sigDoc) 
    {
        m_sigDoc = sigDoc;
    }
    
    /**
     * Accessor for id attribute
     * @return value of id attribute
     */
    public String getId() {
        return m_id;
    }
    
    /**
     * Mutator for id attribute
     * @param str new value for id attribute
     * @throws DigiDocException for validation errors
     */    
    public void setId(String str) 
        throws DigiDocException
    {
        DigiDocException ex = validateId(str);
        if(ex != null)
            throw ex;
        m_id = str;
    }
    
    /**
     * Accessor for origContent attribute
     * @return value of origContent attribute
     */
    public byte[] getOrigContent() {
        return m_origContent;
    }
    
    /**
     * Mutator for origContent attribute
     * @param str new value for origContent attribute
     */    
    public void setOrigContent(byte[] data) 
    {
        m_origContent = data;
    }
    
    /**
     * Helper method to validate an id
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateId(String str)
    {
        DigiDocException ex = null;
        if(str == null)
            ex = new DigiDocException(DigiDocException.ERR_SIGNATURE_ID, 
                "Id is a required attribute", null);
        return ex;
    }
    
    /**
     * Accessor for signedInfo attribute
     * @return value of signedInfo attribute
     */
    public SignedInfo getSignedInfo() {
        return m_signedInfo;
    }
    
    /**
     * Mutator for signedInfo attribute
     * @param str new value for signedInfo attribute
     * @throws DigiDocException for validation errors
     */    
    public void setSignedInfo(SignedInfo si) 
        throws DigiDocException
    {
        //ArrayList errs = si.validate();
        //if(!errs.isEmpty())
        //    throw (DigiDocException)errs.get(0);
        m_signedInfo = si;
    }

    /**
     * Checks if this signature uses EC key
     * @return true if EC signature
     */
    public boolean isEllipticCurveSiganture()
    {
    	return (m_signedInfo != null) && (m_signedInfo.getSignatureMethod() != null) && 
    			(m_signedInfo.getSignatureMethod().equals(SignedDoc.ECDSA_SHA1_SIGNATURE_METHOD) ||
    					m_signedInfo.getSignatureMethod().equals(SignedDoc.ECDSA_SHA224_SIGNATURE_METHOD) ||
    					m_signedInfo.getSignatureMethod().equals(SignedDoc.ECDSA_SHA256_SIGNATURE_METHOD) ||
    					m_signedInfo.getSignatureMethod().equals(SignedDoc.ECDSA_SHA384_SIGNATURE_METHOD) ||
    					m_signedInfo.getSignatureMethod().equals(SignedDoc.ECDSA_SHA512_SIGNATURE_METHOD));
    }
    
    /**
     * Returnes true if alternate digest matches instead of the real one
     * @return true if alternate digest matches instead of the real one
     * @deprecated alternate digest is still calculated but it is no longer optional check.
     * Error is allways egenrated if real digest doesn't match.
     */
    @Deprecated
    public boolean getAltDigestMatch() { return m_bAltDigMatch; }
    
    /**
     * Set flag to indicate that alternate digest matches instead of the real one
     * @param b flag to indicate that alternate digest matches instead of the real one
     */
    public void setAltDigestMatch(boolean b) { m_bAltDigMatch = b; }

    /**
     * Calculates the SignedInfo digest
     * @return SignedInfo digest
     */
    public byte[] calculateSignedInfoDigest()
        throws DigiDocException
    {
        return m_signedInfo.calculateDigest();
    }
    
    /**
     * Calculates the SignedInfo xml to sign
     * @return SignedInfo xml
     */
    public byte[] calculateSignedInfoXML()
        throws DigiDocException
    {
    	DigiDocXmlGenFactory genFac = new DigiDocXmlGenFactory(m_sigDoc);
        return genFac.signedInfoToXML(this, m_signedInfo);
    }
    
    /**
     * Returns HTTP_FROM value. This value is used
     * as a http header during ocsp requests. It must be
     * set before calling DigiDocGenFactory.finalizeSignature()
     * @return HTTP_FROM value
     */
    public String getHttpFrom() { return m_httpFrom; }
    
    /**
     * Sets HTTP_FROM value. This value is used
     * as a http header during ocsp requests. It must be
     * set before calling DigiDocGenFactory.finalizeSignature()
     * @param s HTTP_FROM value
     */
    public void setHttpFrom(String s) { m_httpFrom = s; }
    
    /**
     * Accessor for signatureValue attribute
     * @return value of signatureValue attribute
     */
    public SignatureValue getSignatureValue() {
        return m_signatureValue;
    }
    
    /**
     * Mutator for signatureValue attribute
     * @param str new value for signatureValue attribute
     * @throws DigiDocException for validation errors
     */    
    public void setSignatureValue(SignatureValue sv) 
        throws DigiDocException
    {
        //ArrayList errs = sv.validate();
        //if(!errs.isEmpty())
        //    throw (DigiDocException)errs.get(0);
        m_signatureValue = sv;
        // VS: bug fix on 14.05.2008
        m_origContent = null;
    }
    
    /**
     * Creates a new SignatureValue object
     * of this signature
     * @param sigv signatures byte data
     * @throws DigiDocException for validation errors
     */    
    public void setSignatureValue(byte[] sigv) 
        throws DigiDocException
    {
        SignatureValue sv = new SignatureValue(this, sigv);
        setSignatureValue(sv);
    }
    
    /**
     * Accessor for keyInfo attribute
     * @return value of keyInfo attribute
     */
    public KeyInfo getKeyInfo() {
        return m_keyInfo;
    }
    
    /**
     * Mutator for keyInfo attribute
     * @param str new value for keyInfo attribute
     * @throws DigiDocException for validation errors
     */    
    public void setKeyInfo(KeyInfo ki) 
        throws DigiDocException
    {
        //ArrayList errs = ki.validate();
        //if(!errs.isEmpty())
        //    throw (DigiDocException)errs.get(0);
        m_keyInfo = ki;
    }
    
    /**
     * Accessor for signedProperties attribute
     * @return value of signedProperties attribute
     */
    public SignedProperties getSignedProperties() {
        return m_sigProp;
    }
    
    /**
     * Mutator for signedProperties attribute
     * @param str new value for signedProperties attribute
     * @throws DigiDocException for validation errors
     */    
    public void setSignedProperties(SignedProperties sp) 
        throws DigiDocException
    {
        //ArrayList errs = sp.validate();
        //if(!errs.isEmpty())
        //    throw (DigiDocException)errs.get(0);
        m_sigProp = sp;
    }
    
    /**
     * Accessor for unsignedProperties attribute
     * @return value of unsignedProperties attribute
     */
    public UnsignedProperties getUnsignedProperties() {
        return m_unsigProp;
    }
    
    /**
     * Mutator for unsignedProperties attribute
     * @param str new value for unsignedProperties attribute
     * @throws DigiDocException for validation errors
     */    
    public void setUnsignedProperties(UnsignedProperties usp) 
        throws DigiDocException
    {
        //ArrayList errs = usp.validate();
        //if(!errs.isEmpty())
        //    throw (DigiDocException)errs.get(0);
        m_unsigProp = usp;
    }
    
    /**
     * return the count of CertID objects
     * @return count of CertID objects
     */
    public int countCertIDs()
    {
        return ((m_certIds == null) ? 0 : m_certIds.size());
    }
    
    /**
     * Adds a new CertID object
     * @param cid new object to be added
     */
    public void addCertID(CertID cid)
    {
    	if(m_certIds == null)
    		m_certIds = new ArrayList();
    	cid.setSignature(this);
    	m_certIds.add(cid);
    }
    
    /**
     * Retrieves CertID element with the desired index
     * @param idx CertID index
     * @return CertID element or null if not found
     */
    public CertID getCertID(int idx)
    {
    	if(m_certIds != null && idx < m_certIds.size()) {
    		return (CertID)m_certIds.get(idx);
    	}
    	return null; // not found
    }
    
    /**
     * Retrieves the last CertID element
     * @return CertID element or null if not found
     */
    public CertID getLastCertId()
    {
    	if(m_certIds != null && m_certIds.size() > 0) {
    		return (CertID)m_certIds.get(m_certIds.size()-1);
    	}
    	return null; // not found
    }
    
    /**
     * Retrieves CertID element with the desired type
     * @param type CertID type
     * @return CertID element or null if not found
     */
    public CertID getCertIdOfType(int type)
    {
    	for(int i = 0; (m_certIds != null) && (i < m_certIds.size()); i++) {
    		CertID cid = (CertID)m_certIds.get(i);
    		if(cid.getType() == type)
    			return cid;
    	}
    	return null; // not found
    }
    
    /**
     * Retrieves CertID element with the desired type.
     * If not found creates a new one with this type.
     * @param type CertID type
     * @return CertID element
     * @throws DigiDocException for validation errors
     */
    public CertID getOrCreateCertIdOfType(int type)
    	throws DigiDocException
    {
    	CertID cid = getCertIdOfType(type);
    	if(cid == null) {
    		cid = new CertID();
    		cid.setType(type);
    		addCertID(cid);
    	}
    	return cid; // not found
    }
    
    /**
     * return the count of CertValue objects
     * @return count of CertValues objects
     */
    public int countCertValues()
    {
        return ((m_certValues == null) ? 0 : m_certValues.size());
    }
    
    /**
     * Adds a new CertValue object
     * @param cval new object to be added
     */
    public void addCertValue(CertValue cval)
    {
    	if(m_certValues == null)
    		m_certValues = new ArrayList();
    	cval.setSignature(this);
    	m_certValues.add(cval);
    }
    
    /**
     * Retrieves CertValue element with the desired index
     * @param idx CertValue index
     * @return CertValue element or null if not found
     */
    public CertValue getCertValue(int idx)
    {
    	if(m_certValues != null && idx < m_certValues.size()) {
    		return (CertValue)m_certValues.get(idx);
    	} else
    	return null; // not found
    }
    
    /**
     * Retrieves the last CertValue element 
     * @return CertValue element or null if not found
     */
    public CertValue getLastCertValue()
    {
    	if(m_certValues != null && m_certValues.size() > 0) {
    		return (CertValue)m_certValues.get(m_certValues.size()-1);
    	} else
    		return null; // not found
    }
    
    /**
     * Retrieves CertValue element with the desired type
     * @param type CertValue type
     * @return CertValue element or null if not found
     */
    public CertValue getCertValueOfType(int type)
    {
    	for(int i = 0; (m_certValues != null) && (i < m_certValues.size()); i++) {
    		CertValue cval = (CertValue)m_certValues.get(i);
    		if(cval.getType() == type)
    			return cval;
    	}
    	return null; // not found
    }
    
    /**
     * Retrieves CertValue element with the desired type.
     * If not found creates a new one with this type.
     * @param type CertValue type
     * @return CertValue element
     * @throws DigiDocException for validation errors
     */
    public CertValue getOrCreateCertValueOfType(int type)
    	throws DigiDocException
    {
    	CertValue cval = getCertValueOfType(type);
    	if(cval == null) {
    		cval = new CertValue();
    		cval.setType(type);
    		addCertValue(cval);
    	}
    	return cval; // not found
    }
    
    /**
     * Returns the first CertValue with the given serial
     * number that has been attached to this signature in
     * digidoc document. This could be either the signers 
     * cert, OCSP responders cert or one of the TSA certs.
     * @param serNo certificates serial number
     * @return found CertValue or null
     */
    public CertValue findCertValueWithSerial(BigInteger serNo)
    {
    	for(int i = 0; (m_certValues != null) && (i < m_certValues.size()); i++) {
    		CertValue cval = (CertValue)m_certValues.get(i);
    		if(cval.getCert().getSerialNumber().equals(serNo))
    			return cval;
    	}
    	return null;
    }
	
    /**
     * Retrieves OCSP respoinders certificate
     * @return OCSP respoinders certificate
     */
    public X509Certificate findResponderCert()
    {
    	CertValue cval = getCertValueOfType(CertValue.CERTVAL_TYPE_RESPONDER);
    	if(cval != null)
    		return cval.getCert();
    	else
    		return null;
    }
    
    /**
     * Retrieves TSA certificates
     * @return TSA certificates
     */
    public ArrayList findTSACerts()
    {
    	ArrayList vec = new ArrayList();
    	for(int i = 0; (m_certValues != null) && (i < m_certValues.size()); i++) {
    		CertValue cval = (CertValue)m_certValues.get(i);
    		if(cval.getType() == CertValue.CERTVAL_TYPE_TSA)
    			vec.add(cval.getCert());
    	}
    	return vec;
    }
    
    /**
     * return the count of TimestampInfo objects
     * @return count of TimestampInfo objects
     */
    public int countTimestampInfos()
    {
        return ((m_timestamps == null) ? 0 : m_timestamps.size());
    }
    
    /**
     * Adds a new TimestampInfo object
     * @param ts new object to be added
     */
    public void addTimestampInfo(TimestampInfo ts)
    {
    	if(m_timestamps == null)
    		m_timestamps = new ArrayList();
    	ts.setSignature(this);
    	m_timestamps.add(ts);
    }
    
    /**
     * Retrieves TimestampInfo element with the desired index
     * @param idx TimestampInfo index
     * @return TimestampInfo element or null if not found
     */
    public TimestampInfo getTimestampInfo(int idx)
    {
    	if(m_timestamps != null && idx < m_timestamps.size()) {
    		return (TimestampInfo)m_timestamps.get(idx);
    	} else
    		return null; // not found
    }
    
    /**
     * Retrieves the last TimestampInfo element 
     * @return TimestampInfo element or null if not found
     */
    public TimestampInfo getLastTimestampInfo()
    {
    	if(m_timestamps != null && m_timestamps.size() > 0) {
    		return (TimestampInfo)m_timestamps.get(m_timestamps.size()-1);
    	} else
    		return null; // not found
    }
    
    /**
     * Retrieves TimestampInfo element with the desired type
     * @param type TimestampInfo type
     * @return TimestampInfo element or null if not found
     */
    public TimestampInfo getTimestampInfoOfType(int type)
    {
    	for(int i = 0; (m_timestamps != null) && (i < m_timestamps.size()); i++) {
    		TimestampInfo ts = (TimestampInfo)m_timestamps.get(i);
    		if(ts.getType() == type)
    			return ts;
    	}
    	return null; // not found
    }
    
    /**
     * Retrieves TimestampInfo element with the desired type.
     * If not found creates a new one with this type.
     * @param type TimestampInfo type
     * @return TimestampInfo element
     * @throws DigiDocException for validation errors
     */
    public TimestampInfo getOrCreateTimestampInfoOfType(int type)
    	throws DigiDocException
    {
    	TimestampInfo ts = getTimestampInfoOfType(type);
    	if(ts == null) {
    		ts = new TimestampInfo();
    		ts.setType(type);
    		addTimestampInfo(ts);
    	}
    	return ts; // not found
    }
    
    /**
     * Accessor for path attribute
     * @return value of path attribute
     */
    public String getPath()
    {
    	return m_path;
    }
    
    /**
     * Mutator for path attribute
     * @param s new value for path attribute
     */
    public void setPath(String s)
    {
    	m_path = s;
    }
    
    /**
     * Accessor for profile attribute
     * @return value of profile attribute
     */
    public String getProfile()
    {
    	return m_profile;
    }
    
    /**
     * Mutator for profile attribute
     * @param s new value for profile attribute
     */
    public void setProfile(String s)
    {
    	m_profile = s;
    }
    
    /**
     * Accessor for comment attribute
     * @return value of comment attribute
     */
    public String getComment()
    {
    	return m_comment;
    }
    
    /**
     * Mutator for comment attribute
     * @param s new value for comment attribute
     */
    public void setComment(String s)
    {
    	m_comment = s;
    }
    
    /**
     * Gets confirmation and adds the corresponding
     * members that carry the returned info to
     * this signature
     * @throws DigiDocException for all errors
     */
    public void getConfirmation()
        throws DigiDocException
    {
    	if(m_sigDoc.getFormat().equals(SignedDoc.FORMAT_DIGIDOC_XML) ||
    			m_sigDoc.getFormat().equals(SignedDoc.FORMAT_SK_XML)) {
    		if(m_profile == null || m_profile.equalsIgnoreCase(SignedDoc.BDOC_PROFILE_TM)) {
    	  DigiDocGenFactory.finalizeXadesT(m_sigDoc, this);
    	  DigiDocGenFactory.finalizeXadesC(m_sigDoc, this);
    	  DigiDocGenFactory.finalizeXadesXL_TM(m_sigDoc, this);
    		}
    	} else {
    		String profile = m_profile;
    		if(profile == null)
    			profile = m_sigDoc.getProfile();
    		if(profile == null || profile.trim().length() == 0)
				profile = ConfigManager.instance().getStringProperty("DIGIDOC_DEFAULT_PROFILE", SignedDoc.BDOC_PROFILE_TM);
    		DigiDocGenFactory.finalizeSignature(m_sigDoc, this, m_signatureValue.getValue(), profile);
    	} 
        // reset original content since we just added to confirmation
        if(m_origContent != null) {
          DigiDocXmlGenFactory genFac = new DigiDocXmlGenFactory(m_sigDoc);
	      String str = new String(m_origContent);
	      int idx1 = str.indexOf("</SignedProperties>");
	      if(idx1 != -1) {
		  try {
		    ByteArrayOutputStream bos = new ByteArrayOutputStream();
		    bos.write(m_origContent, 0, idx1);
		    bos.write("</SignedProperties>".getBytes());
		    bos.write(genFac.unsignedPropertiesToXML(this, m_unsigProp));
		    bos.write("</QualifyingProperties></Object></Signature>".getBytes());
		    m_origContent = bos.toByteArray();
		  } catch(java.io.IOException ex) {
		    DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_GET_CONF);
		  }
	      }	    
        }
    }
    
    /**
     * Checks if this signature defines that if complies with bdoc 2.0 nonce
     * @return true if this signature defines bdoc 2.0 nonce policy compliance
     */
    public boolean hasBdoc2NoncePolicy()
    {
    	if(m_sigProp != null &&
    	   m_sigProp.getSignaturePolicyIdentifier() != null &&
    	   m_sigProp.getSignaturePolicyIdentifier().getSignaturePolicyId() != null &&
    	   m_sigProp.getSignaturePolicyIdentifier().getSignaturePolicyId().getSigPolicyId() != null &&
    	   m_sigProp.getSignaturePolicyIdentifier().getSignaturePolicyId().getSigPolicyId().getIdentifier() != null) {
    		Identifier id = m_sigProp.getSignaturePolicyIdentifier().getSignaturePolicyId().getSigPolicyId().getIdentifier();
    		if(id.getQualifier().equals(Identifier.OIDAsURN) &&
    		   id.getUri().equals(Identifier.BDOC_210_OID))
    		  return true;
    	}
    	return false;
    }
    
    /** 
     * Verifies and validates this signature. Returns a list of both
     * validation and verification errors.
     * @param lerrs list to be filled with DigiDocException objects
     * @return true if signature is ok
     */
    public boolean verify(SignedDoc sdoc, ArrayList lerrs)
    {
    	boolean bOk = true;
    	// validation
    	ArrayList lerrs1 = validate();
    	if(lerrs1 != null && lerrs1.size() > 0) {
    		bOk = false;
    		if(lerrs != null)
    			lerrs.addAll(lerrs1);
    	}
    	// verification
    	lerrs1 = new ArrayList();
    	boolean bOk1 = DigiDocVerifyFactory.verifySignature(sdoc, this, lerrs1);
    	if(!bOk1) bOk = false;
    	if(lerrs1 != null && lerrs1.size() > 0) {
    		bOk = false;
    		if(lerrs != null)
    			lerrs.addAll(lerrs1);
    	}
        return bOk;
    }
    
    /** 
     * Verifies this signature
     * @param sdoc parent doc object
     * @param checkDate Date on which to check the signature validity
     * @param demandConfirmation true if you demand OCSP confirmation from
     * every signature
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList verify(SignedDoc sdoc, boolean checkDate, boolean demandConfirmation)
    {
    	Date do1 = null, dt1 = null, dt2 = null;
        ArrayList lerrs = new ArrayList();
        boolean bOk = DigiDocVerifyFactory.verifySignature(sdoc, this, lerrs);
        return lerrs;
    }


    /**
     * Helper method to validate the whole
     * Signature object
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList validate()
    {
        ArrayList errs = new ArrayList();
        DigiDocException ex = validateId(m_id);
        if(ex != null)
            errs.add(ex);
        ArrayList e = null;
        if(m_signedInfo != null) {
        	e = m_signedInfo.validate();
        } else {
        	errs.add(new DigiDocException(DigiDocException.ERR_PARSE_XML, "Missing SignedInfo element", null));
        }
        if(e != null && !e.isEmpty())
            errs.addAll(e);
        if(m_signatureValue != null)
          e = m_signatureValue.validate();
        if(e != null && !e.isEmpty())
            errs.addAll(e);
        if(m_keyInfo != null) {
        	e = m_keyInfo.validate();
        } else {
        	errs.add(new DigiDocException(DigiDocException.ERR_PARSE_XML, "Missing KeyInfo element", null));
        }
        if(e != null && !e.isEmpty())
            errs.addAll(e);
        if(m_sigProp != null) {
          e = m_sigProp.validate();
          if(!e.isEmpty())
            errs.addAll(e);
        }
        if(m_unsigProp != null) {
            e = m_unsigProp.validate();
            if(!e.isEmpty())
                errs.addAll(e);
        }
        return errs;
    }
    

    /** returns QualifyingProperties object */
	public QualifyingProperties getQualifyingProperties() {
		return m_qualProp;
	}
	
	/** sets QualifyingProperties object */
	public void setQualifyingProperties(QualifyingProperties prop) {
		m_qualProp = prop;
	}
	
	/**
     * Accessor for signedInfo attribute
     * @return value of signedInfo attribute
     */
    public String getSubject() {
        return m_keyInfo.getSubjectFirstName() + " " + m_keyInfo.getSubjectLastName() + " " + m_keyInfo.getSubjectPersonalCode();
    }
    
    public ArrayList getErrors() { return m_errs; }
    public void setErrors(ArrayList l) { m_errs = l; }
    
    public String getStatus() {
    	if(m_errs == null || m_errs.size() == 0) {
    		if(m_signatureValue != null && m_signatureValue.getValue() != null)
    		   return "OK";
    		else
    			return "INCOMPLETE";
    	} else
    		return "ERROR";
    }
    
    /**
     * Retrieves the signature production timestamp from first ocsp response
     * @return ocsp response produced-at time if exists
     */
    public Date getSignatureProducedAtTime()
    {
    	if(m_unsigProp != null) {
    		Notary not = m_unsigProp.getNotary();
    		if(not != null)
    			return not.getProducedAt();
    	}
    	return null;
    }
    
    /**
     * Converts Signature object to String representation 
     * mainly for debugging purposes
     */
    public String toString()
    {
    	try {
    		DigiDocXmlGenFactory genFac = new DigiDocXmlGenFactory(m_sigDoc);
    		return new String(genFac.signatureToXML(this), "UTF-8");
    	} catch(Exception ex) {
    		m_logger.error("Error converting Signature to string: " + ex);
    	}
    	return null;
    }
}
