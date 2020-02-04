package com.ro.dss.validation.service.base.custom;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.OfflineCRLSource;

public class COfflineCRLSource extends OfflineCRLSource {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public COfflineCRLSource() {
		// TODO Auto-generated constructor stub
	}

	public void addCRL(byte[] binaries, RevocationOrigin origin) {
		addCRLBinary(new CRLBinary(binaries), origin);
	}

	public void storeCRL(CRLBinary crlBinary, CRLToken crlToken) {
		storeCRLToken(crlBinary, crlToken);
	}
}
