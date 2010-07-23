/*
 * SignedDataObjectProperties.java
 * PROJECT: JDigiDoc
 * DESCRIPTION: corresponds to XAdES SignedDataObjectProperties structure
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
import java.util.ArrayList;

/**
 * Models an XML-DSIG/ETSI SignedDataObjectProperties structure. 
 * This structure is used to hold various properties of all
 * signed data objects referenced by one signature.
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class SignedDataObjectProperties implements Serializable
{
	private static final long serialVersionUID = 1L;
	/** DataObjectFormat elements */
	private ArrayList m_dataObjectFormats; 
	// other XAdES structure elements not supported
	
	/**
	 * Default constructor for SignedDataObjectProperties
	 */
	public SignedDataObjectProperties()
	{
		m_dataObjectFormats = null;
	}
	
	/**
     * return the count of DataObjectFormat objects
     * @return count of DataObjectFormat objects
     */
    public int countDataObjectFormats()
    {
        return ((m_dataObjectFormats == null) ? 0 : m_dataObjectFormats.size());
    }
    
    /**
     * Adds a new DataObjectFormat object
     * @param dof new object to be added
     */
    public void addDataObjectFormat(DataObjectFormat dof)
    {
    	if(m_dataObjectFormats == null)
    		m_dataObjectFormats = new ArrayList();
    	m_dataObjectFormats.add(dof);
    }
    
    /**
     * Retrieves DataObjectFormat element with the desired index
     * @param idx DataObjectFormat index
     * @return DataObjectFormat element or null if not found
     */
    public DataObjectFormat getDataObjectFormat(int idx)
    {
    	if(m_dataObjectFormats != null && idx < m_dataObjectFormats.size()) {
    		return (DataObjectFormat)m_dataObjectFormats.get(idx);
    	}
    	return null; // not found
    }
    
    /**
     * Retrieves the last DataObjectFormat element
     * @return DataObjectFormat element or null if not found
     */
    public DataObjectFormat getLastDataObjectFormat()
    {
    	if(m_dataObjectFormats != null && m_dataObjectFormats.size() > 0) {
    		return (DataObjectFormat)m_dataObjectFormats.get(m_dataObjectFormats.size()-1);
    	}
    	return null; // not found
    }

    /**
     * Helper method to validate the whole
     * DataObjectFormat object
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList validate()
    {
        ArrayList errs = new ArrayList();
        for(int i = 0; (m_dataObjectFormats != null) && (i < m_dataObjectFormats.size()); i++) {
        	DataObjectFormat dof = (DataObjectFormat)m_dataObjectFormats.get(i);
        	ArrayList errs2 = dof.validate();
            if(errs2 != null && errs2.size() > 0)
                errs.addAll(errs2);
        }
        return errs;
    }
}
