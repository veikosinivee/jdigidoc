/*
 * DigiDocFactory.java
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

package ee.sk.digidoc.factory;
import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.Signature;
import ee.sk.digidoc.SignedDoc;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Interface for reading and writing
 * DigiDoc files
 * @author  Veiko Sinivee
 * @version 1.0
 */
public interface DigiDocFactory 
{
    /** 
     * initializes the implementation class 
     */
    public void init()
        throws DigiDocException;

    /**
	 * Checks filename extension if this is bdoc / asic-e
	 * @param fname filename
	 * @return true if this is bdoc / asic-e
	 */
	public boolean isBdocExtension(String fname);
	
    /**
     * Reads in a DigiDoc file
     * @param fileName file name
     * @return signed document object if successfully parsed
     */
    public SignedDoc readSignedDoc(String fileName) 
        throws DigiDocException;

    /**
	 * Reads in a DigiDoc file.This method reads only data in digidoc format. Not BDOC!
	 * @param digiDocStream opened stream with DigiDoc data
	 * The user must open and close it.
	 * @return signed document object if successfully parsed
	 */
	public SignedDoc readDigiDocFromStream(InputStream digiDocStream)
    	throws DigiDocException;
        
	/**
	 * Reads in a DigiDoc or BDOC from stream. In case of BDOC a Zip stream will be 
	 * constructed to read this input stream. In case of ddoc a normal saxparsing stream
	 * will be used.
	 * @param is opened stream with DigiDoc/BDOC data
	 * The user must open and close it.
	 * @param isBdoc true if bdoc is read
	 * @return signed document object if successfully parsed
	 */
	public SignedDoc readSignedDocFromStreamOfType(InputStream is, boolean isBdoc)
		throws DigiDocException;
	
	/**
	 * Reads in a DigiDoc or BDOC file
	 * @param fname filename
	 * @param isBdoc true if bdoc is read
	 * @return signed document object if successfully parsed
	 */
	public SignedDoc readSignedDocOfType(String fname, boolean isBdoc)
		throws DigiDocException;
	
	/**
	 * Reads in a DigiDoc or BDOC file
	 * @param fname filename
	 * @param isBdoc true if bdoc is read
	 * @param lerr list of errors to be filled. If not null then no exceptions are thrown
	 * but returned in this array
	 * @return signed document object if successfully parsed
	 */
	public SignedDoc readSignedDocOfType(String fname, boolean isBdoc, List lerr)
		throws DigiDocException;
	
	/**
	 * Reads in a DigiDoc or BDOC from stream. In case of BDOC a Zip stream will be 
	 * constructed to read this input stream. In case of ddoc a normal saxparsing stream
	 * will be used.
	 * @param is opened stream with DigiDoc/BDOC data
	 * The user must open and close it.
	 * @param isBdoc true if bdoc is read
	 * @param lerr list of errors to be filled. If not null then no exceptions are thrown
	 * but returned in this array
	 * @return signed document object if successfully parsed
	 */
	public SignedDoc readSignedDocFromStreamOfType(InputStream is, boolean isBdoc, List lerr)
		throws DigiDocException;
	
    /**
	 * Reads in only one <Signature>
	 * @param sdoc SignedDoc to add this signature to
	 * @param sigStream opened stream with Signature data
	 * The user must open and close it.
	 * @return signed document object if successfully parsed
	 */
	public Signature readSignature(SignedDoc sdoc, InputStream sigStream)
		throws DigiDocException;
	
	/**
	 * Reads in a DigiDoc file
	 * @param digiSigStream opened stream with Signature data
	 * The user must open and close it.
	 * @return signed document object if successfully parsed
	 */
	public Signature readSignature(InputStream digiSigStream)
	throws DigiDocException;
	
	/**
	 * Set temp dir used to cache data files.
	 * @param s directory name
	 */
	public void setTempDir(String s);

	
}
