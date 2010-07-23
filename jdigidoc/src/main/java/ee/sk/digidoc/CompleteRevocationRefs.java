/*
 * CompleteRevocationRefs.java
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

package ee.sk.digidoc;
import java.io.Serializable;
import java.util.Vector;
import java.util.ArrayList;
import ee.sk.utils.ConvertUtils;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Models the ETSI CompleteRevocationRefs element
 * This contains some data from the OCSP response
 * and it's digest
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class CompleteRevocationRefs implements Serializable
{
	private static final long serialVersionUID = 1L;
	
    /** vector of ocsp refs */
    private Vector m_ocspRefs;
    /** parent object - UnsignedProperties ref */
    private UnsignedProperties m_unsignedProps;
    
    /** 
     * Creates new CompleteRevocationRefs 
     * Initializes everything to null
     */
    public CompleteRevocationRefs() {
    	m_ocspRefs = null;
        m_unsignedProps = null;
    }

    
    /**
     * Accessor for UnsignedProperties attribute
     * @return value of UnsignedProperties attribute
     */
    public UnsignedProperties getUnsignedProperties()
    {
    	return m_unsignedProps;
    }
    
    /**
     * Mutator for UnsignedProperties attribute
     * @param uprops value of UnsignedProperties attribute
     */
    public void setUnsignedProperties(UnsignedProperties uprops)
    {
    	m_unsignedProps = uprops;
    }
    
 
    /**
     * Get the n-th OcspRef object
     * @param nIdx OcspRef index
     * @return OcspRef object
     */
    public OcspRef getOcspRefById(int nIdx)
    {
    	if(m_ocspRefs != null && nIdx < m_ocspRefs.size())
    		return (OcspRef)m_ocspRefs.elementAt(nIdx);
    	else
    		return null;
    }
    
    /**
     * Get OcspRef object by uri
     * @param uri OcspRef uri
     * @return OcspRef object
     */
    public OcspRef getOcspRefByUri(String uri)
    {
    	for(int i = 0; (m_ocspRefs != null) && (i < m_ocspRefs.size()); i++) {
    		OcspRef orf = (OcspRef)m_ocspRefs.elementAt(i);
    		if(orf.getUri().equals(uri))
    			return orf;
    	}
    	return null;
    }
    
    /**
     * Get the last OcspRef object
     * @return OcspRef object
     */
    public OcspRef getLastOcspRef()
    {
    	if(m_ocspRefs != null && m_ocspRefs.size() > 0)
    		return (OcspRef)m_ocspRefs.elementAt(m_ocspRefs.size()-1);
    	else
    		return null;
    }
    
    /**
     * Add a new OcspRef
     * @param orf OcspRef object
     */
    public void addOcspRef(OcspRef orf)
    {
    	if(m_ocspRefs == null)
    		m_ocspRefs = new Vector();
    	m_ocspRefs.add(orf);
    }
    
    /**
     * Count the number of OcspRef objects
     * @return number of OcspRef objects
     */
    public int countOcspRefs() { return (m_ocspRefs != null) ? m_ocspRefs.size() : 0; }
    
    /**
     * Helper method to validate the whole
     * CompleteRevocationRefs object
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList validate()
    {
        ArrayList errs = new ArrayList();
        for(int i = 0; (m_ocspRefs != null) && (i < m_ocspRefs.size()); i++) {
        	OcspRef orf = (OcspRef)m_ocspRefs.elementAt(i);
        	ArrayList errs2 = orf.validate();
        	if(errs2 != null && errs2.size() > 0)
        		errs.addAll(errs2);
        }
        return errs;
    }
    


}
