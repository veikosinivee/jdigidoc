/*
 * ManifestFileEntry
 * PROJECT: JDigiDoc
 * DESCRIPTION: <manifest:file-entry> element of manifest.xml file. 
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
import ee.sk.utils.ConvertUtils;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Models an BDOC format manifest.xml files <file-entry> element. 
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class ManifestFileEntry implements Serializable
{
	private static final long serialVersionUID = 1L;
    /** media-type attribute */
    private String m_mediaType;
    /** full-path attribute */
    private String m_fullPath;
    
    /**
     * Constructor for ManifestFileEntry
     * @param mediaType media-type attribute
     * @param fullPath full-path attribute
     */
    public ManifestFileEntry(String mediaType, String fullPath)
    {
    	m_mediaType = mediaType;
    	m_fullPath = fullPath;
    }

    /**
     * accessor for  media-type attribute
     * @return media-type attribute
     */
    public String getMediaType() {
    	return m_mediaType;
    }
    
    /**
     * accessor for full-path attribute
     * @return full-path attribute
     */
    public String getFullPath() {
    	return m_fullPath;
    }
    
    /**
     * mutator for  media-type attribute
     * @param s media-type attribute
     */
    public void setMediaType(String s) {
    	m_mediaType = s;
    }
    
    /**
     * mutator for full-path attribute
     * @param s full-path attribute
     */
    public void setFullPath(String s) {
    	m_fullPath = s;
    }
    
    /**
     * Converts the ManifestFileEntry to XML form
     * @return XML representation of ManifestFileEntry
     */
    public byte[] toXML()
        throws DigiDocException
    {
        ByteArrayOutputStream bos = 
                new ByteArrayOutputStream();
        try {
            bos.write(ConvertUtils.str2data("<manifest:file-entry "));
            bos.write(ConvertUtils.str2data("manifest:media-type=\""));
            bos.write(ConvertUtils.str2data(m_mediaType));
            bos.write(ConvertUtils.str2data("\" manifest:full-path=\""));
            bos.write(ConvertUtils.str2data(ConvertUtils.escapeXmlSymbols(m_fullPath)));
            bos.write(ConvertUtils.str2data("\" />\n"));
         } catch(IOException ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_XML_CONVERT);
        }
        return bos.toByteArray();
    }

    /**
     * return the stringified form of ManifestFileEntry
     * @return ManifestFileEntry string representation
     */
    public String toString() {
        String str = null;
        try {
            str = new String(toXML());
        } catch(Exception ex) {}
        return str;
    } 
}
