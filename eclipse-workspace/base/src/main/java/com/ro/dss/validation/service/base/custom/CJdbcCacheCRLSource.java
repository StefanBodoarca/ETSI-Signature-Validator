package com.ro.dss.validation.service.base.custom;

import eu.europa.esig.dss.service.crl.JdbcCacheCRLSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;

public class CJdbcCacheCRLSource extends JdbcCacheCRLSource {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public CJdbcCacheCRLSource() {
		
	}
	
	public void cInsertRevocation(CRLToken token) {
		insertRevocation(token);
	}
}
