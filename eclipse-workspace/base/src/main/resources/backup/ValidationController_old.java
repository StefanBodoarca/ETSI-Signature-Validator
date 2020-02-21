package com.ro.dss.validation.service.base.controller;

import java.io.File;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.ro.dss.validation.service.base.model.CrtClass;
import com.ro.dss.validation.service.base.model.FileObjClass;
import com.ro.dss.validation.service.base.model.ValidationObject;
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

	@Autowired
	private CertificateVerifier certificateVerifier;

	@RequestMapping(value = "/validation", method = RequestMethod.POST)
	public ResponseEntity<Object> validateSignature(@RequestBody ValidationObject customJsonObject) {
		CertificateVerifier cv = certificateVerifier;
		// System.out.println(customJsonObject.getOriginalDocumentName());

		Map<String, String> tempMap = new HashMap<>();
		tempMap.put(customJsonObject.getOriginalDocumentName(), customJsonObject.getOriginalDocument());
		tempMap.put(customJsonObject.getSignedDocumentName(), customJsonObject.getSignedDocument());

		// RemoteDocument signedDocument = new
		// RemoteDocument(customJsonObject.getSignedDocument().getBytes(), MimeType.PDF,
		// customJsonObject.getSignedDocumentName());
		// RemoteDocument originalDocument = new
		// RemoteDocument(customJsonObject.getOriginalDocument().getBytes(),
		// MimeType.PDF, customJsonObject.getOriginalDocumentName());

		// SignedDocumentValidator documentValidator =
		// SignedDocumentValidator.fromDocument(signedDocument);

		// List<DSSDocument> originalDocsList = new ArrayList<DSSDocument>();
		// originalDocsList.add(originalDocument);

//		documentValidator.setCertificateVerifier(cv);
//		documentValidator.setDetachedContents(originalDocsList);
//		Reports reports = documentValidator.validateDocument();

		// String xmlSimpleReport = reports.getXmlDetailedReport();
//		RemoteDocumentValidationService remoteDocumentValidationService = new RemoteDocumentValidationService();
//		remoteDocumentValidationService.setVerifier(cv);
//		ReportsDTO reports = remoteDocumentValidationService.validateDocument(signedDocument, originalDocument, null);
//		

		DSSDocument originalDocument = new InMemoryDocument(Base64.getDecoder().decode(customJsonObject.getOriginalDocument().getBytes()),
				customJsonObject.getOriginalDocumentName(), MimeType.PDF);
		DSSDocument signedDocument = new InMemoryDocument(Base64.getDecoder().decode(customJsonObject.getSignedDocument().getBytes()),
				customJsonObject.getSignedDocumentName(), MimeType.PDF);
		// SignedDocumentValidator documentValidator =
		// SignedDocumentValidator.fromDocument(signedDocument);

		SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(signedDocument);

		List<DSSDocument> originalDocsList = new ArrayList<DSSDocument>();
		originalDocsList.add(originalDocument);

		documentValidator.setCertificateVerifier(cv);
		documentValidator.setDetachedContents(originalDocsList);
		Reports reports = documentValidator.validateDocument();

		return new ResponseEntity<>(reports.getXmlSimpleReport(), HttpStatus.OK);
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
		return new ResponseEntity<>(reports.getXmlSimpleReport(), HttpStatus.OK);
	}

	@RequestMapping(value = "/validation-check-doc", method = RequestMethod.GET)
	public ResponseEntity<Object> validateCheckDoc() {
		DSSDocument myDocument = new FileDocument(new File("src/main/resources/test.pdf"));

		// We create an instance of DocumentValidator
		// It will automatically select the supported validator from the classpath
		SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(myDocument);
		//PDFDocumentValidator docV = new PDFDocumentValidator(document);
		//PDFDocumentValidator docValidator = new PDFDocumentValidator(myDocument);
		
		return new ResponseEntity<>("76543ymiomr681768", HttpStatus.OK);
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
	
	@RequestMapping(value = "/certificate/validation", method = RequestMethod.GET)
	public ResponseEntity<Object> validateCrt() {
		// Firstly, we load the certificate to be validated
		CertificateToken token = DSSUtils.loadCertificate(new File("src/main/resources/server.crt"));

		// We need a certificate verifier and configure it  (see specific chapter about the CertificateVerifier configuration)
		CertificateVerifier cv = certificateVerifier;

		// We create an instance of the CertificateValidator with the certificate
		CertificateValidator validator = CertificateValidator.fromCertificate(token);
		validator.setCertificateVerifier(cv);

		// We execute the validation
		CertificateReports certificateReports = validator.validate();

		// We have 3 reports
		// The diagnostic data which contains all used and static data
		DiagnosticData diagnosticData = certificateReports.getDiagnosticData();

		// The detailed report which is the result of the process of the diagnostic data and the validation policy
		DetailedReport detailedReport = certificateReports.getDetailedReport();

		// The simple report is a summary of the detailed report or diagnostic data (more user-friendly)
		SimpleCertificateReport simpleReport = certificateReports.getSimpleReport();
		
		return new ResponseEntity<>(simpleReport, HttpStatus.OK);
	}
}
