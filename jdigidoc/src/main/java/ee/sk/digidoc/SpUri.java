/*
 * SpUri.java
 * PROJECT: JDigiDoc
 * DESCRIPTION: corresponds to XAdES SpUri structure
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
 * Models an XML-DSIG/ETSI SpUri structure. 
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class SpUri extends SigPolicyQualifier implements Serializable
{
	private static final long serialVersionUID = 1L;
	/** URI */
	private String m_uri;

	public SpUri(String uri)
	{
		m_uri = uri;
	}
	
	/**
     * Accessor for SPURI content
     * @return value of SPURI content
     */
	public String getUri()
	{
		return m_uri;
	}
	
	/**
     * Mutator for SPURI content
     * @param uri new value for SPURI content
     */    
    public void setUri(String uri) 
    {
    	m_uri = uri;
    }
    
}
