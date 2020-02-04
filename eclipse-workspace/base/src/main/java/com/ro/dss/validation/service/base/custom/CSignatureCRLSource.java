package com.ro.dss.validation.service.base.custom;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.validation.SignatureCRLSource;

public class CSignatureCRLSource extends SignatureCRLSource {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public CSignatureCRLSource() {
		
	}
	
	public void storeCRL(CRLBinary crlBinary, CRLToken crlToken) {
		storeCRLToken(crlBinary, crlToken);
	}
}
