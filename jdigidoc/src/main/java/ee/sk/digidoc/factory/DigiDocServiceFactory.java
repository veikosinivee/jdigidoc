package ee.sk.digidoc.factory;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Authenticator;
import java.net.URL;
import java.net.URLConnection;
import java.security.cert.X509Certificate;
import org.apache.log4j.Logger;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;

import ee.sk.digidoc.*;
import ee.sk.utils.ConfigManager;
import ee.sk.utils.ConvertUtils;

/**
 * Factory class to handle generating M-ID signatures 
 * using DigiDocService webservice
 * @author Veiko Sinivee
 * @deprecated not fully supported
 */
public class DigiDocServiceFactory 
{
	private static Logger m_logger = Logger.getLogger(DigiDocServiceFactory.class);
	
	public static final String STAT_OUTSTANDING_TRANSACTION = "OUTSTANDING_TRANSACTION";
	public static final String STAT_SIGNATURE = "SIGNATURE";
	public static final String STAT_ERROR = "ERROR";
    		
	private static final String g_xmlHdr1 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:d=\"http://www.sk.ee/DigiDocService/DigiDocService_2_3.wsdl\" xmlns:mss=\"http://www.sk.ee:8096/MSSP_GW/MSSP_GW.wsdl\"><SOAP-ENV:Body SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><d:MobileCreateSignature>";
	private static final String g_xmlEnd1 = "</d:MobileCreateSignature></SOAP-ENV:Body></SOAP-ENV:Envelope>";
	private static final String g_xmlHdr2 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:d=\"http://www.sk.ee/DigiDocService/DigiDocService_2_3.wsdl\" xmlns:mss=\"http://www.sk.ee:8096/MSSP_GW/MSSP_GW.wsdl\"><SOAP-ENV:Body SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><d:GetMobileCreateSignatureStatus>";
	private static final String g_xmlEnd2 = "</d:GetMobileCreateSignatureStatus></SOAP-ENV:Body></SOAP-ENV:Envelope>";
	
	private static void addElem(StringBuffer xml, String tag, String value)
	{
		if(value != null && value.trim().length() > 0) {
		  xml.append("<");
		  xml.append(tag);
		  xml.append(">");
		  xml.append(value);
		  xml.append("</");
		  xml.append(tag);
		  xml.append(">");
		}
	}
	
	private static String findElemValue(String msg, String tag)
	{
		int nIdx1 = 0, nIdx2 = 0;
		if(msg != null && tag != null) {
			nIdx1 = msg.indexOf("<" + tag);
			if(nIdx1 != -1) {
				while(msg.charAt(nIdx1) != '>') nIdx1++;
				nIdx1++;
				nIdx2 = msg.indexOf("</" + tag, nIdx1);
				if(nIdx1 > 0 && nIdx2 > 0)
					return msg.substring(nIdx1, nIdx2);
			}
		}
		return null;
	}
	
	private static String findAttrValue(String msg, String attr)
	{
		int nIdx1 = 0, nIdx2 = 0;
		if(msg != null && attr != null) {
			nIdx1 = msg.indexOf(attr);
			if(nIdx1 != -1) {
				while(msg.charAt(nIdx1) != '=') nIdx1++;
				nIdx1 ++;
				if(msg.charAt(nIdx1) == '\"') nIdx1++;
				nIdx2 = msg.indexOf("\"", nIdx1);
				if(nIdx1 > 0 && nIdx2 > 0)
					return msg.substring(nIdx1, nIdx2);
			}
		}
		return null;
	}
	
	/**
     * Sends soap message and returns result
     * @param algorithm digest algorithm
     * @param digest digest value
     * @param url TSA server utl
     * @return response
     */
    private static String pullUrl(String url, String msg)
    {
    	try {
    		URL uUrl = new URL(url);
    		// https authentication
    		String storename = ConfigManager.instance().getProperty("DDS_TRUSTSTORE");
    		String storpass = ConfigManager.instance().getProperty("DDS_STOREAPASS");
    		String stortype = ConfigManager.instance().getProperty("DDS_STORETYPE");
    		if(storename != null) {
    			if(m_logger.isDebugEnabled())
        			m_logger.debug("https truststore: " + storename + "/" + stortype);
    			System.setProperty("javax.net.ssl.trustStore", storename);
    			System.setProperty("javax.net.ssl.trustStorePassword", storpass);
    			System.setProperty("javax.net.ssl.trustStoreType", stortype);
    		}
    		// http authentication
        	String ocspAuth = ConfigManager.instance().getProperty("DIGIDOC_OCSP_AUTH");
        	if(ocspAuth != null) {
        		String ocspAuthUser = ConfigManager.instance().getProperty("DIGIDOC_OCSP_AUTH_USER");
        		String ocspAuthPasswd = ConfigManager.instance().getProperty("DIGIDOC_OCSP_AUTH_PASSWD");
        		if(m_logger.isDebugEnabled())
        			m_logger.debug("http auth: " + ocspAuthUser + "/" + ocspAuthPasswd);
        		HttpAuthenticator auth = new HttpAuthenticator(ocspAuthUser, ocspAuthPasswd);
        		Authenticator.setDefault(auth);
        	}
    		if(m_logger.isDebugEnabled())
	    		m_logger.debug("Connecting to: " + url);
            URLConnection con = uUrl.openConnection();
            if(m_logger.isDebugEnabled())
	    		m_logger.debug("Conn opened: " + ((con != null) ? "OK" : "NULL"));
            con.setAllowUserInteraction(false);
            con.setUseCaches(false);
            con.setDoOutput(true);
            con.setDoInput(true);
            // send the OCSP request
            con.setRequestProperty("Content-Type", "text/xml; charset=utf-8");
            con.setRequestProperty("User-Agent", SignedDoc.LIB_NAME + " / " + SignedDoc.LIB_VERSION);
            con.setRequestProperty("SOAPAction", "");
            OutputStream os = con.getOutputStream();
            if(m_logger.isDebugEnabled())
	    		m_logger.debug("OS: " + ((os != null) ? "OK" : "NULL"));
            os.write(msg.getBytes("UTF-8"));
            os.close();
            if(m_logger.isDebugEnabled())
	    		m_logger.debug("Wrote: " + msg.length());
            // read the response
            InputStream is = con.getInputStream();
            int cl = con.getContentLength();
            byte[] bresp = null;
            if(m_logger.isDebugEnabled())
	    		m_logger.debug("Recv: " + cl + " bytes");
            if(cl > 0) {
                int avail = 0;
                do {
                    avail = is.available();
                    byte[] data = new byte[avail];
                    int rc = is.read(data);
                    if(bresp == null) {
                        bresp = new byte[rc];
                        System.arraycopy(data, 0, bresp, 0, rc);
                    } else {
                        byte[] tmp = new byte[bresp.length + rc];
                        System.arraycopy(bresp, 0, tmp, 0, bresp.length);
                        System.arraycopy(data, 0, tmp, bresp.length, rc);
                        bresp = tmp;
                    }
                    cl -= rc;
                } while(cl > 0);
            }
            is.close();
            if(m_logger.isDebugEnabled())
	    		m_logger.debug("Received: " + ((bresp != null) ? bresp.length : 0) + " bytes");
            String resp = new String(bresp, "UTF-8");
            return resp;
    	} catch(Exception ex) {
    		m_logger.error("Soap error: " + ex);
    		
    	}
    	return null;
    }
    
	/**
	 * Starts M-ID signing session
	 * @param sdoc signed doc to add a new signature to
	 * @param sIdCode personal id code of signer
	 * @param sPhoneNo phone number
	 * @param sLang language
	 * @param sServiceName service nama param to digidocservice
	 * @param sManifest manifest of signature
	 * @param sCity city
	 * @param sState state or province
	 * @param sZip postal index
	 * @param sCountry country name
	 * @param sbChallenge returned challenge code
	 * @return session code
	 * @throws DigiDocException
	 * @deprecated not fully supported
	 */
	public static String ddsSign(SignedDoc sdoc, 
            String sIdCode, String sPhoneNo,
            String sLang, String sServiceName,
            String sManifest, String sCity, 
            String sState, String sZip, 
            String sCountry, StringBuffer sbChallenge)
		throws DigiDocException
	{
		String sSessCode = null;
		
		if(sdoc == null)
	    	throw new DigiDocException(DigiDocException.ERR_DIGIDOC_SERVICE, "Missing SignedDoc object", null);
	    if(sIdCode == null || sIdCode.trim().length() < 11)
	    	throw new DigiDocException(DigiDocException.ERR_DIGIDOC_SERVICE, "Missing or invalid personal id-code", null);
	    if(sPhoneNo == null || sPhoneNo.trim().length() < 5) // min 5 kohaline mobiili nr ?
	    	throw new DigiDocException(DigiDocException.ERR_DIGIDOC_SERVICE, "Missing or invalid phone number", null);
	    if(sCountry == null || sCountry.trim().length() < 2)
	    	throw new DigiDocException(DigiDocException.ERR_DIGIDOC_SERVICE, "Missing or invalid country code", null);
	    ConfigManager cfg = ConfigManager.instance();
		String sUrl = cfg.getProperty("DDS_URL");
		//String sProxyHost = cfg.getProperty("DIGIDOC_PROXY_HOST");
		//String sProxyPort = cfg.getProperty("DIGIDOC_PROXY_PORT");
		// compose soap msg
		StringBuffer sbMsg = new StringBuffer(g_xmlHdr1);
		addElem(sbMsg, "IDCode", sIdCode);
		addElem(sbMsg, "SignersCountry", sCountry);
		addElem(sbMsg, "PhoneNo", sPhoneNo);
		addElem(sbMsg, "Language", sLang);
		addElem(sbMsg, "ServiceName", sServiceName);
		addElem(sbMsg, "Role", sManifest);
		addElem(sbMsg, "City", sCity);
		addElem(sbMsg, "StateOrProvince", sState);
		addElem(sbMsg, "PostalCode", sZip);
		addElem(sbMsg, "CountryName", sCountry);
	    sbMsg.append("<DataFiles>");
	    for(int i = 0; i < sdoc.countDataFiles(); i++) {
	        DataFile df = sdoc.getDataFile(i);
	        sbMsg.append("<DataFileDigest>");
	        addElem(sbMsg, "Id", df.getId());
	        addElem(sbMsg, "DigestType", "sha1");
	        String sHash = Base64Util.encode(df.getDigest());
	        addElem(sbMsg, "DigestValue", sHash);
	        sbMsg.append("</DataFileDigest>");
	    }
	    sbMsg.append("</DataFiles>");
	    addElem(sbMsg, "Format", sdoc.getFormat());
	    addElem(sbMsg, "Version", sdoc.getVersion());
	    String sId = sdoc.getNewSignatureId();
	    addElem(sbMsg, "SignatureID", sId);
	    addElem(sbMsg, "MessagingMode", "asynchClientServer");
	    addElem(sbMsg, "AsyncConfiguration", "0");
		sbMsg.append(g_xmlEnd1);
		// send soap message
		if(m_logger.isDebugEnabled())
			m_logger.debug("Sending:\n---\n" + sbMsg.toString() + "\n---\n");
		String sResp = pullUrl(sUrl, sbMsg.toString());
		if(m_logger.isDebugEnabled())
			m_logger.debug("Received:\n---\n" + sResp + "\n---\n");
		if(sResp != null && sResp.trim().length() > 0) {
			sSessCode = findElemValue(sResp, "Sesscode");
			String s = findElemValue(sResp, "ChallengeID");
			if(s != null)
				sbChallenge.append(s);
		}
		return sSessCode;
	}
	
	/**
	 * Sends soap message to query M-ID signing process status
	 * @param sdoc signed doc object
	 * @param sSesscode session code
	 * @return status as string constant
	 * @throws DigiDocException
	 * @deprecated not fully supported
	 */
	public static String ddsGetStatus(SignedDoc sdoc, String sSesscode)
		throws DigiDocException
	{
		String sStatus = null;
		
		if(sdoc == null)
			throw new DigiDocException(DigiDocException.ERR_DIGIDOC_SERVICE, "Missing SignedDoc object", null);
		if(sSesscode == null || sSesscode.trim().length() == 0)
			throw new DigiDocException(DigiDocException.ERR_DIGIDOC_SERVICE, "Missing or invalid  session code", null);
		ConfigManager cfg = ConfigManager.instance();
		String sUrl = cfg.getProperty("DDS_URL");
		//String sProxyHost = cfg.getProperty("DIGIDOC_PROXY_HOST");
		//String sProxyPort = cfg.getProperty("DIGIDOC_PROXY_PORT");
		// compose soap msg
		StringBuffer sbMsg = new StringBuffer(g_xmlHdr2);
		addElem(sbMsg, "Sesscode", sSesscode);
		addElem(sbMsg, "WaitSignature", "false");
		sbMsg.append(g_xmlEnd2);
		// send soap message
		if(m_logger.isDebugEnabled())
			m_logger.debug("Sending:\n---\n" + sbMsg.toString() + "\n---\n");
		String sResp = pullUrl(sUrl, sbMsg.toString());
		if(m_logger.isDebugEnabled())
			m_logger.debug("Received:\n---\n" + sResp + "\n---\n");
		if(sResp != null && sResp.trim().length() > 0) {
			sStatus = findElemValue(sResp, "Status");
			if(sStatus != null && sStatus.equals(STAT_SIGNATURE)) {
			  String s = findElemValue(sResp, "Signature");
			  if(s != null) {
				String sSig = ConvertUtils.unescapeXmlSymbols(s);
				String sId = findAttrValue(sSig, "Id");
				if(m_logger.isDebugEnabled())
					m_logger.debug("Signature: " + sId +"\n---\n" + sSig + "\n---\n");
				Signature sig = new Signature(sdoc);
				sig.setId(sId);
				try {
				sig.setOrigContent(sSig.getBytes("UTF-8"));
				} catch(Exception ex) {
					m_logger.error("Error adding signature: " + ex);
					DigiDocException.handleException(ex, DigiDocException.ERR_DIGIDOC_SERVICE);
				}
				sdoc.addSignature(sig);
			  }
			}
		}
		return sStatus;
	}
	
	
}
