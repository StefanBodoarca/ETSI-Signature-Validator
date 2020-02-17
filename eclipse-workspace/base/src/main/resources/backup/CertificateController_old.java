package com.ro.dss.validation.service.base.controller;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.util.List;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.ws.rs.BadRequestException;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.ro.dss.validation.service.base.custom.COfflineCRLSource;
import com.ro.dss.validation.service.base.model.CrtCalssBase64;
import com.ro.dss.validation.service.base.model.CrtCalssBase64Chain;
import com.ro.dss.validation.service.base.model.CrtClassMultipartFile;
import com.ro.dss.validation.service.base.model.CrtClassMultipartFileChain;
import com.ro.dss.validation.service.base.model.FileObjClass;
import com.ro.dss.validation.service.base.model.ValidationObject;
import com.ro.dss.validation.service.base.serviceclass.FOPService;
import com.ro.dss.validation.service.base.utils.AppUtils;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.crl.CRLValidity;
import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.ExternalResourcesCRLSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateValidator;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.ListCRLSource;
import eu.europa.esig.dss.validation.SignatureCRLSource;
import eu.europa.esig.dss.validation.reports.CertificateReports;

@RestController
public class CertificateController {
	private static final Logger LOG = Logger.getLogger(CertificateController.class.getName());
	
	@Autowired
	private CertificateVerifier certificateVerifier;
	
	@Autowired
	private FOPService fopService;
	
	@Autowired
	private byte[] getCRList;
	
	@Autowired
	private CRLValidity crlValidity;
	
	
	private byte[] CRL_LIST = null;
	
	
	private CertificateToken token = null;
	private CertificateVerifier cv = null;
	private CertificateValidator validator = null;
	private CertificateReports certificateReports = null;
	private DiagnosticData diagnosticData = null;
	private DetailedReport detailedReport = null;
	private SimpleCertificateReport simpleReport = null;
	
	@RequestMapping(value = "/certificate/base64/validation", method = RequestMethod.POST)
	public ResponseEntity<Object> validateCrtBase64(@RequestBody CrtCalssBase64 crtBase64JsonObject) {
		token = DSSUtils.loadCertificateFromBase64EncodedString(crtBase64JsonObject.getBase64CrtFile());
	    validateAndFillData(certificateVerifier);
		return new ResponseEntity<>(simpleReport, HttpStatus.OK);
	}
	
	@RequestMapping(value = "/certificate/multipartfile/validation", method = RequestMethod.POST)
	public ResponseEntity<Object> validateCrtMultipartFile(@ModelAttribute CrtClassMultipartFile crtMultipartFile) {		
		token = getCertificate(crtMultipartFile.getCrtFile());
		validateAndFillData(certificateVerifier);
		return new ResponseEntity<>(simpleReport, HttpStatus.OK);
	}
	
	@RequestMapping(value = "/certificate/chain/base64/validation", method = RequestMethod.POST)
	public ResponseEntity<Object> validateCrtBase64Chain(@RequestBody CrtCalssBase64Chain crtBase64JsonObject) {
		token = DSSUtils.loadCertificateFromBase64EncodedString(crtBase64JsonObject.getBase64CrtFile());
		CertificateVerifier localCv = certificateVerifier;
		List<String> certificateChainFiles = crtBase64JsonObject.getBase64ChainFiles();
		if (Utils.isCollectionNotEmpty(certificateChainFiles)) {
			CertificateSource adjunctCertSource = new CommonCertificateSource();
			for (String fileStr : certificateChainFiles) {
				CertificateToken certificateChainItem = DSSUtils.loadCertificateFromBase64EncodedString(fileStr);;
				if (certificateChainItem != null) {
					adjunctCertSource.addCertificate(certificateChainItem);
				}
			}
			localCv.setAdjunctCertSource(adjunctCertSource);
		}
		validateAndFillData(localCv);
		return new ResponseEntity<>(simpleReport, HttpStatus.OK);
	}
	
	@RequestMapping(value = "/certificate/chain/multipartfile/validation", method = RequestMethod.POST)
	public ResponseEntity<Object> validateCrtMultipartFileChain(@ModelAttribute CrtClassMultipartFileChain crtMultipartFiles) {		
		token = getCertificate(crtMultipartFiles.getCrtFile());
		CertificateVerifier localCv = certificateVerifier;
		List<MultipartFile> certificateChainFiles = crtMultipartFiles.getCrtChainFiles();
		if (Utils.isCollectionNotEmpty(certificateChainFiles)) {
			CertificateSource adjunctCertSource = new CommonCertificateSource();
			for (MultipartFile file : certificateChainFiles) {
				CertificateToken certificateChainItem = getCertificate(file);
				if (certificateChainItem != null) {
					adjunctCertSource.addCertificate(certificateChainItem);
				}
			}
			localCv.setAdjunctCertSource(adjunctCertSource);
		}

		LOG.info("Start certificate validation");
		validateAndFillData(localCv);
		return new ResponseEntity<>(simpleReport, HttpStatus.OK);
	}
	
	@RequestMapping(value = "/download-simple-report", method = RequestMethod.GET)
	public void downloadSimpleReport(HttpSession session, HttpServletResponse response) {
		try {
			String simpleReportRes = simpleReport.toString();

			response.setContentType(MimeType.PDF.getMimeTypeString());
			response.setHeader("Content-Disposition", "attachment; filename=DSS-Simple-report.pdf");

			fopService.generateSimpleReport(simpleReportRes, response.getOutputStream());
		} catch (Exception e) {
			LOG.error("An error occurred while generating pdf for simple report : " + e.getMessage(), e);
		}
	}
	
	@RequestMapping(value = "/download-xml-simple-report")
	public void downloadDiagnosticData(HttpSession session, HttpServletResponse response) {
		String report = certificateReports.getXmlSimpleReport();

		response.setContentType(MimeType.XML.getMimeTypeString());
		response.setHeader("Content-Disposition", "attachment; filename=DSS-Diagnotic-data.xml");
		try {
			Utils.copy(new ByteArrayInputStream(report.getBytes()), response.getOutputStream());
		} catch (IOException e) {
			LOG.error("An error occured while outputing diagnostic data : " + e.getMessage(), e);
		}
	}
	
	private void validateAndFillData(CertificateVerifier certVerifier) {
		cv = certVerifier;
//		COfflineCRLSource cOfflineCRLSource = (COfflineCRLSource) cv.getCrlSource();
//		cOfflineCRLSource.storeCRL(new CRLBinary(getCRList), new CRLToken(token, crlValidity));
//		cv.setCrlSource(cOfflineCRLSource);
//		cv.setSignatureCRLSource(new ListCRLSource(cOfflineCRLSource));
		validator = CertificateValidator.fromCertificate(token);
		validator.setCertificateVerifier(cv);
		certificateReports = validator.validate();
		diagnosticData = certificateReports.getDiagnosticData();
		detailedReport = certificateReports.getDetailedReport();
		simpleReport = certificateReports.getSimpleReport();
		
		/////////////////////////#CRLSOURCECHECK
		CRLSource crlSource = cv.getCrlSource();
		SignatureCRLSource signatureCRLSource = cv.getSignatureCRLSource();
	}
	
	private CertificateToken getCertificate(MultipartFile file) {
		try {
			if (file != null && !file.isEmpty()) {
				return DSSUtils.loadCertificate(file.getBytes());
			}
		} catch (DSSException | IOException e) {
			LOG.error("Cannot convert file to X509 Certificate", e);
			LOG.error("Unsupported certificate format for file '" + file.getOriginalFilename() + "'");
		}
		return null;
	}
}
