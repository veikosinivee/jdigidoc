/*
 * SignaturePolicyIdentifier.java
 * PROJECT: JDigiDoc
 * DESCRIPTION: corresponds to XAdES SignaturePolicyIdentifier structure
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

/**
 * Models an XML-DSIG/ETSI SignaturePolicyIdentifier structure. 
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class SignaturePolicyIdentifier implements Serializable
{
	private static final long serialVersionUID = 1L;
	/** SignaturePolicyId - id null then SignaturePolicyImplied */
	private SignaturePolicyId m_sigPolicyId;
	
	/**
	 * Constructor for SignaturePolicyIdentifier
	 * @param sigPolicyId SignaturePolicyId object.
	 * If null then SignaturePolicyImplied
	 */
	public SignaturePolicyIdentifier(SignaturePolicyId sigPolicyId)
	{
		m_sigPolicyId = sigPolicyId;
	}
	
	/**
     * Accessor for SignaturePolicyId element
     * @return value of SignaturePolicyId element
     */
	public SignaturePolicyId getSignaturePolicyId()
	{
		return m_sigPolicyId;
	}
	
	/**
     * Mutator for Description content
     * @param str new value for Description content
     */    
    public void setSignaturePolicyId(SignaturePolicyId spi) 
    {
    	m_sigPolicyId = spi;
    }
    
}
