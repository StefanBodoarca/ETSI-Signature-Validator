package com.ro.dss.validation.service.base.controller;

import java.io.File;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.ro.dss.validation.service.base.model.CrtClassMultipartFile;
import com.ro.dss.validation.service.base.model.FileObjClass;
import com.ro.dss.validation.service.base.model.ValidationObject;
import com.ro.dss.validation.service.base.serviceclass.FOPService;
import com.ro.dss.validation.service.base.utils.AppUtils;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateValidator;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.validation.common.RemoteDocumentValidationService;
import eu.europa.esig.dss.ws.validation.dto.DataToValidateDTO;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;
import eu.europa.esig.dss.ws.validation.rest.RestDocumentValidationServiceImpl;
import eu.europa.esig.dss.ws.validation.rest.client.RestDocumentValidationService;

@RestController
public class ValidationController {
	private static final Logger LOG = Logger.getLogger(CertificateController.class.getName());

	@Autowired
	private CertificateVerifier certificateVerifier;
	
	@Autowired
	private FOPService fopService;
	
	private String simpleReport = null;

	@RequestMapping(value = "/validation", method = RequestMethod.POST)
	public ResponseEntity<Object> validateSignature(@RequestBody ValidationObject customJsonObject) {

		return null;
	}

	@RequestMapping(value = "/validation-form-data", method = RequestMethod.POST)
	public ResponseEntity<Object> validateSignatureFormData(@ModelAttribute FileObjClass customReceivedFileObject) {
		System.out.println(customReceivedFileObject.getOriginalFileName());
		System.out.println(customReceivedFileObject.getOriginalFile().toString());
		System.out.println(customReceivedFileObject.getOriginalFile().getOriginalFilename());

		CertificateVerifier cv = certificateVerifier;
		DSSDocument signedDocument = AppUtils.toDSSDocument(customReceivedFileObject.getSignedFile());
		DSSDocument originalDocument = AppUtils.toDSSDocument(customReceivedFileObject.getOriginalFile());
		SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(signedDocument);

		List<DSSDocument> originalDocsList = new ArrayList<DSSDocument>();
		originalDocsList.add(originalDocument);

		documentValidator.setCertificateVerifier(cv);
		documentValidator.setDetachedContents(originalDocsList);
		Reports reports = documentValidator.validateDocument();
		simpleReport = reports.getXmlSimpleReport();
		return new ResponseEntity<>(reports.getXmlSimpleReport(), HttpStatus.OK);
	}
	
	@RequestMapping(value = "/validation-tsa-form-data", method = RequestMethod.POST)
	public ResponseEntity<Object> validateSignatureFormDataWithTsa(@ModelAttribute FileObjClass customReceivedFileObject) {

		CertificateVerifier cv = certificateVerifier;
		if(customReceivedFileObject.getTsa().equals("true")) {
			cv.setIncludeTimestampTokenValues(true);
		}
		DSSDocument signedDocument = AppUtils.toDSSDocument(customReceivedFileObject.getSignedFile());
		DSSDocument originalDocument = AppUtils.toDSSDocument(customReceivedFileObject.getOriginalFile());
		SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(signedDocument);

		List<DSSDocument> originalDocsList = new ArrayList<DSSDocument>();
		originalDocsList.add(originalDocument);

		documentValidator.setCertificateVerifier(cv);
		documentValidator.setDetachedContents(originalDocsList);
		Reports reports = documentValidator.validateDocument();
		simpleReport = reports.getXmlSimpleReport();
		return new ResponseEntity<>(reports.getXmlSimpleReport(), HttpStatus.OK);
	}

	@RequestMapping(value = "/validation-check-doc", method = RequestMethod.GET)
	public ResponseEntity<Object> validateCheckDoc() {

		return null;
	}
	
	@RequestMapping(value = "/validation/download-simple-report", method = RequestMethod.GET)
	public void downloadSimpleReport(HttpSession session, HttpServletResponse response) {
		
		if(simpleReport != null) {
			try {
				String simpleReportRes = simpleReport;

				response.setContentType(MimeType.PDF.getMimeTypeString());
				response.setHeader("Content-Disposition", "attachment; filename=DSS-Simple-report.pdf");

				fopService.generateSimpleReport(simpleReportRes, response.getOutputStream());
			} catch (Exception e) {
				LOG.error("An error occurred while generating pdf for simple report : " + e.getMessage(), e);
			}
		}
	}
	
	@RequestMapping(value = "/validation/validateSignature", method = RequestMethod.POST)
	public ResponseEntity<Object> validateLong(@RequestBody ValidationObject customJsonObject) {
		RestDocumentValidationService validationService;
		RestDocumentValidationServiceImpl service = new RestDocumentValidationServiceImpl();
		RemoteDocumentValidationService remoteDocumentVService = new RemoteDocumentValidationService();
		
		remoteDocumentVService.setVerifier(certificateVerifier);
		service.setValidationService(remoteDocumentVService);
		validationService = service;
		
		RemoteDocument signedFile = new RemoteDocument(Base64.getDecoder().decode(customJsonObject.getSignedDocument().getBytes()),customJsonObject.getSignedDocumentName());
		RemoteDocument originalFile = new RemoteDocument(Base64.getDecoder().decode(customJsonObject.getOriginalDocument().getBytes()),customJsonObject.getOriginalDocumentName());
		DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, originalFile, null);
		WSReportsDTO result = validationService.validateSignature(toValidate);
		
		return new ResponseEntity<>(result.getSimpleReport(), HttpStatus.OK);
	}
}
