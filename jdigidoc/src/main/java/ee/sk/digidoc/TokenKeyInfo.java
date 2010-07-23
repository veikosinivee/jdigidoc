/*
 * TokenKeyInfo.java
 * PROJECT: JDigiDoc
 * DESCRIPTION: Key info on a token (smartcard etc.)
 * that can be used for signing. 
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
import java.security.cert.X509Certificate;
import iaik.pkcs.pkcs11.Token;
import org.apache.log4j.Logger;

import ee.sk.utils.ConvertUtils;

/**
 * Holds key info that represents a key on a cryptographic token (smartcard etc.)
 * @author Veiko Sinivee
 */
public class TokenKeyInfo implements Serializable
{
	private static final long serialVersionUID = 1L;
	/** some order number */
	private int m_nr;
	/** token info */
	private transient Token m_token;
	/** slot id */
	private long m_nSlot;
	/** key id */
	private byte[] m_id;
	/** certificate */
	private X509Certificate m_cert;
	private String m_label;
	private static Logger m_logger = Logger.getLogger(TokenKeyInfo.class);
	
	/**
	 * Constructor for TokenKeyInfo
	 * @param nr order number
	 * @param nSlot slot id
	 * @param tok token info
	 * @param id key id
	 * @param label pkcs11 cert  object label 
	 * @param cert certificate
	 */
	public TokenKeyInfo(int nr, long nSlot, Token tok, byte[] id, String label, X509Certificate cert)
	{
		m_nSlot = nSlot;
		m_token = tok;
		m_id = id;
		m_label = label;
		m_cert = cert;
	}
	
	// accessors
	public int getNr() { return m_nr; }
	public byte[] getId() { return m_id; }
	public Token getToken() { return m_token; }
	public long getSlot() { return m_nSlot; }
	public X509Certificate getCert() { return m_cert; }
	public String getLabel() { return m_label; }
	public String getTokenName() { 
		try {
			if(m_token != null)
			return m_token.getTokenInfo().getLabel(); 
		} catch(Exception ex) {
			m_logger.error("Error reading token name: " + ex);
		}
		return null;
	}
	public String getCertName() { 
		try {
			if(m_cert != null)
				return SignedDoc.getCommonName(m_cert.getSubjectDN().getName());
		} catch(Exception ex) {
			m_logger.error("Error reading token name: " + ex);
		}
		return null;
	}
	
	public String getCertHex()
	{
		try {
			if(m_cert != null)
				return SignedDoc.bin2hex(m_cert.getEncoded());
			else
				return null;
		} catch(Exception ex) {
			m_logger.error("Error encoding cert: " + ex);
		}
		return null;
	}
	
	public String getIdHex()
	{
		try {
			if(m_id != null)
				return SignedDoc.bin2hex(m_id);
			else
				return null;
		} catch(Exception ex) {
			m_logger.error("Error encoding id: " + ex);
		}
		return null;
	}
	
	public String getCertSerial()
	{
		try {
			if(m_cert != null)
				return m_cert.getSerialNumber().toString();
			else
				return null;
		} catch(Exception ex) {
			m_logger.error("Error reading cert serial: " + ex);
		}
		return null;
	}
	
	public boolean isSignatureKey()
	{
		return ConvertUtils.isSignatureCert(m_cert);
	}
	
	public boolean isEncryptKey()
	{
		return ConvertUtils.isEncryptCert(m_cert);
	}
}
