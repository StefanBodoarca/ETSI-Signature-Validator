package com.ro.dss.validation.service.base.controller;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.ws.rs.BadRequestException;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.ro.dss.validation.service.base.model.CrtClassMultipartFile;
import com.ro.dss.validation.service.base.model.FileObjClass;
import com.ro.dss.validation.service.base.model.FileObjClassMultipleDocs;
import com.ro.dss.validation.service.base.model.TokenDTO;
import com.ro.dss.validation.service.base.model.ValidationObject;
import com.ro.dss.validation.service.base.serviceclass.FOPService;
import com.ro.dss.validation.service.base.utils.AppUtils;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.AbstractTokenProxy;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateValidator;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.executor.ValidationLevel;
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
	private static final Logger logger = Logger.getLogger(CertificateController.class.getName());

	@Autowired
	private CertificateVerifier certificateVerifier;

	@Autowired
	private FOPService fopService;

	private Reports reports = null;
	private CertificateToken token = null;

	private CertificateVerifier crtVerifier = null;
	private CertificateValidator validator = null;
	private CertificateReports certificateReports = null;

	@RequestMapping(value = "/validation/validation-form-data", method = RequestMethod.POST)
	public ResponseEntity<Object> validateSignatureFormData(@ModelAttribute FileObjClass customReceivedFileObject) {

		CertificateVerifier cv = certificateVerifier;
		token = getCertificate(customReceivedFileObject.getCrtFile());
		if (token != null) {
			validateAndFillData(certificateVerifier);
		}
		DSSDocument signedDocument = AppUtils.toDSSDocument(customReceivedFileObject.getSignedFile());
		DSSDocument originalDocument = AppUtils.toDSSDocument(customReceivedFileObject.getOriginalFile());
		SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(signedDocument);

		List<DSSDocument> originalDocsList = new ArrayList<DSSDocument>();
		originalDocsList.add(originalDocument);

		documentValidator.setCertificateVerifier(cv);
		documentValidator.setDetachedContents(originalDocsList);
		reports = documentValidator.validateDocument();
		return new ResponseEntity<>(reports.getXmlSimpleReport(), HttpStatus.OK);
	}

	@RequestMapping(value = "/validation/validation-multiple-docs-form-data", method = RequestMethod.POST)
	public ResponseEntity<Object> validateMultipleDocsSignatureFormData(@ModelAttribute FileObjClassMultipleDocs customReceivedFileObject) {

		CertificateVerifier cv = certificateVerifier;
		token = getCertificate(customReceivedFileObject.getCrtFile());
		DSSDocument signedDocument = AppUtils.toDSSDocument(customReceivedFileObject.getSignedFile());
		List<DSSDocument> originalDocuments = AppUtils.toDSSDocuments(customReceivedFileObject.getOriginalFiles());
		SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(signedDocument);
		
		if(token != null) {
			validateAndFillData(certificateVerifier);
		}
		
		if(customReceivedFileObject.getTsa() != null) {
			if (customReceivedFileObject.getTsa().equals("true")) {
				cv.setIncludeTimestampTokenValues(true);
			}
		}
		
		if(customReceivedFileObject.getValidationLevel() != null) {
			if(customReceivedFileObject.getValidationLevel().equals("BASIC_SIGNATURES")) {
				documentValidator.setValidationLevel(ValidationLevel.BASIC_SIGNATURES);
			}
			if(customReceivedFileObject.getValidationLevel().equals("LONG_TERM_DATA")) {
				documentValidator.setValidationLevel(ValidationLevel.LONG_TERM_DATA);	
			}
			if(customReceivedFileObject.getValidationLevel().equals("ARCHIVAL_DATA")) {
				documentValidator.setValidationLevel(ValidationLevel.ARCHIVAL_DATA);
			}
		}
		
		if (Utils.isCollectionNotEmpty(originalDocuments)) {
			documentValidator.setDetachedContents(originalDocuments);
		}
		
		documentValidator.setCertificateVerifier(cv);
		
		DSSDocument policyFile = AppUtils.toDSSDocument(customReceivedFileObject.getPolicyFile());
		if (policyFile != null) {
			try (InputStream is = policyFile.openStream()) {
				reports = documentValidator.validateDocument(is);
			} catch (IOException e) {
				logger.error(e.getMessage(), e);
			}
		} else {
			reports = documentValidator.validateDocument();
		} 
		
		return new ResponseEntity<>(reports.getXmlSimpleReport(), HttpStatus.OK);
	}

	@RequestMapping(value = "/validation/validation-add-ts-form-data", method = RequestMethod.POST)
	public ResponseEntity<Object> validateSignatureFormDataWithTsa(
			@ModelAttribute FileObjClass customReceivedFileObject) {

		CertificateVerifier cv = certificateVerifier;
		token = getCertificate(customReceivedFileObject.getCrtFile());

		if (token != null) {
			validateAndFillData(certificateVerifier);
		}

		if (customReceivedFileObject.getTsa().equals("true")) {
			cv.setIncludeTimestampTokenValues(true);
		}
		DSSDocument signedDocument = AppUtils.toDSSDocument(customReceivedFileObject.getSignedFile());
		DSSDocument originalDocument = AppUtils.toDSSDocument(customReceivedFileObject.getOriginalFile());
		SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(signedDocument);

		List<DSSDocument> originalDocsList = new ArrayList<DSSDocument>();
		originalDocsList.add(originalDocument);

		documentValidator.setCertificateVerifier(cv);
		documentValidator.setDetachedContents(originalDocsList);
		reports = documentValidator.validateDocument();
		return new ResponseEntity<>(reports.getXmlSimpleReport(), HttpStatus.OK);
	}

	@RequestMapping(value = "/validation/validation-json-data", method = RequestMethod.POST)
	public ResponseEntity<Object> validateJsonData(@RequestBody ValidationObject customJsonObject) {
		RestDocumentValidationService validationService;
		RestDocumentValidationServiceImpl service = new RestDocumentValidationServiceImpl();
		RemoteDocumentValidationService remoteDocumentVService = new RemoteDocumentValidationService();

		remoteDocumentVService.setVerifier(certificateVerifier);
		service.setValidationService(remoteDocumentVService);
		validationService = service;

		RemoteDocument signedFile = new RemoteDocument(
				Base64.getDecoder().decode(customJsonObject.getSignedDocument().getBytes()),
				customJsonObject.getSignedDocumentName());
		RemoteDocument originalFile = new RemoteDocument(
				Base64.getDecoder().decode(customJsonObject.getOriginalDocument().getBytes()),
				customJsonObject.getOriginalDocumentName());
		DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, originalFile, null);
		WSReportsDTO result = validationService.validateSignature(toValidate);

		return new ResponseEntity<>(result.getSimpleReport(), HttpStatus.OK);
	}

	@RequestMapping(value = "/validation/download-diagnostic-data")
	public void downloadDiagnosticData(HttpSession session, HttpServletResponse response) {
		String report = reports.getXmlDiagnosticData();

		response.setContentType(MimeType.XML.getMimeTypeString());
		response.setHeader("Content-Disposition", "attachment; filename=DSS-Diagnotic-data.xml");
		try {
			Utils.copy(new ByteArrayInputStream(report.getBytes()), response.getOutputStream());
		} catch (IOException e) {
			logger.error("An error occured while outputing diagnostic data : " + e.getMessage(), e);
		}
	}
	
	@RequestMapping(value = "/validation/download-etsi-report")
	public void downloadETSIValidationReport(HttpSession session, HttpServletResponse response) {
		
		String report = reports.getXmlValidationReport();

		response.setContentType(MimeType.XML.getMimeTypeString());
		response.setHeader("Content-Disposition", "attachment; filename=DSS-ETSI-report.xml");
		try {
			Utils.copy(new ByteArrayInputStream(report.getBytes()), response.getOutputStream());
		} catch (IOException e) {
			logger.error("An error occured while outputing diagnostic data : " + e.getMessage(), e);
		}
	}

	@RequestMapping(value = "/validation/download-simple-report")
	public void downloadSimpleReport(HttpSession session, HttpServletResponse response) {
		try {
			String simpleReport = reports.getXmlSimpleReport();

			response.setContentType(MimeType.PDF.getMimeTypeString());
			response.setHeader("Content-Disposition", "attachment; filename=DSS-Simple-report.pdf");

			fopService.generateSimpleReport(simpleReport, response.getOutputStream());
		} catch (Exception e) {
			logger.error("An error occurred while generating pdf for simple report : " + e.getMessage(), e);
		}
	}

	@RequestMapping(value = "/validation/download-detailed-report")
	public void downloadDetailedReport(HttpSession session, HttpServletResponse response) {
		try {
			String detailedReport = reports.getXmlDetailedReport();

			response.setContentType(MimeType.PDF.getMimeTypeString());
			response.setHeader("Content-Disposition", "attachment; filename=DSS-Detailed-report.pdf");

			fopService.generateDetailedReport(detailedReport, response.getOutputStream());
		} catch (Exception e) {
			logger.error("An error occurred while generating pdf for detailed report : " + e.getMessage(), e);
		}
	}

	@RequestMapping(value = "/validation/download-certificate")
	public void downloadCertificate(HttpSession session, HttpServletResponse response) {
		if (token != null) {
			DiagnosticData diagnosticData = getDiagnosticData();
			CertificateWrapper certificate = diagnosticData.getUsedCertificateById(token.getDSSIdAsString());

			if (certificate == null) {
				String message = "Certificate not found";
				logger.warn(message);
				throw new BadRequestException(message);
			}

			byte[] crtBytes = certificate.getBinaries();
			String pemCert = DSSUtils.convertToPEM(DSSUtils.loadCertificate(crtBytes));
			TokenDTO certDTO = new TokenDTO(certificate);
			String filename = certDTO.getName().replace(" ", "_") + ".cer";

			response.setContentType(MimeType.CER.getMimeTypeString());
			response.setHeader("Content-Disposition", "attachment; filename=" + filename);
			try {
				Utils.copy(new ByteArrayInputStream(pemCert.getBytes()), response.getOutputStream());
			} catch (IOException e) {
				logger.error("An error occured while downloading certificate : " + e.getMessage(), e);
			}
		} else {
			return;
		}

	}

	@RequestMapping(value = "/validation/download-revocation")
	public void downloadRevocationData(HttpSession session, HttpServletResponse response) {
		String format = "pem";
		DiagnosticData diagnosticData = getDiagnosticData();
		Set<TokenDTO> allRevocations = buildTokenDtos(diagnosticData.getAllRevocationData());
		RevocationWrapper revocationData = diagnosticData.getRevocationById(allRevocations.iterator().next().getId());
		if (revocationData == null) {
			String message = "Revocation data " + allRevocations.iterator().next().getId() + " not found";
			logger.warn(message);
			throw new BadRequestException(message);
		}
		String filename = revocationData.getOrigin().name();
		String mimeType;
		byte[] is;

		if (RevocationType.CRL.equals(revocationData.getRevocationType())) {
			mimeType = MimeType.CRL.getMimeTypeString();
			filename += ".crl";

			if (Utils.areStringsEqualIgnoreCase(format, "pem")) {
				String pem = "-----BEGIN CRL-----\n";
				pem += Utils.toBase64(revocationData.getBinaries());
				pem += revocationData;
				pem += "\n-----END CRL-----";
				is = pem.getBytes();
			} else {
				is = revocationData.getBinaries();
			}
		} else {
			mimeType = MimeType.BINARY.getMimeTypeString();
			filename += ".ocsp";
			is = revocationData.getBinaries();
		}
		response.setContentType(mimeType);
		response.setHeader("Content-Disposition", "attachment; filename=" + filename.replace(" ", "_"));
		try {
			Utils.copy(new ByteArrayInputStream(is), response.getOutputStream());
		} catch (IOException e) {
			logger.error("An error occured while downloading revocation data : " + e.getMessage(), e);
		}
	}

	@RequestMapping(value = "/validation/download-timestamp")
	public void downloadTimestamp(HttpSession session, HttpServletResponse response) {
		String format = "pem";
		DiagnosticData diagnosticData = getDiagnosticDataReports();
		Set<TokenDTO> usedTimestamp = buildTokenDtos(diagnosticData.getTimestampSet());
		TimestampWrapper timestamp = diagnosticData.getTimestampById(usedTimestamp.iterator().next().getId());
		if (timestamp == null) {
			String message = "Timestamp " + usedTimestamp.iterator().next().getId() + " not found";
			logger.warn(message);
			throw new BadRequestException(message);
		}
		TimestampType type = timestamp.getType();

		response.setContentType(MimeType.TST.getMimeTypeString());
		response.setHeader("Content-Disposition", "attachment; filename=" + type.name() + ".tst");
		byte[] is;

		if (Utils.areStringsEqualIgnoreCase(format, "pem")) {
			String pem = "-----BEGIN TIMESTAMP-----\n";
			pem += Utils.toBase64(timestamp.getBinaries());
			pem += "\n-----END TIMESTAMP-----";
			is = pem.getBytes();
		} else {
			is = timestamp.getBinaries();
		}

		try {
			Utils.copy(new ByteArrayInputStream(is), response.getOutputStream());
		} catch (IOException e) {
			logger.error("An error occured while downloading timestamp : " + e.getMessage(), e);
		}
	}

	private DiagnosticData getDiagnosticData() {
		String diagnosticDataXml = certificateReports.getXmlDiagnosticData();
		try {
			XmlDiagnosticData xmlDiagData = DiagnosticDataFacade.newFacade().unmarshall(diagnosticDataXml);
			return new DiagnosticData(xmlDiagData);
		} catch (Exception e) {
			logger.error("An error occured while generating DiagnosticData from XML : " + e.getMessage(), e);
		}
		return null;
	}

	private DiagnosticData getDiagnosticDataReports() {
		String diagnosticDataXml = reports.getXmlDiagnosticData();
		try {
			XmlDiagnosticData xmlDiagData = DiagnosticDataFacade.newFacade().unmarshall(diagnosticDataXml);
			return new DiagnosticData(xmlDiagData);
		} catch (Exception e) {
			logger.error("An error occured while generating DiagnosticData from XML : " + e.getMessage(), e);
		}
		return null;
	}

	private Set<TokenDTO> buildTokenDtos(Set<? extends AbstractTokenProxy> abstractTokens) {
		Set<TokenDTO> tokenDtos = new HashSet<TokenDTO>();
		for (AbstractTokenProxy token : abstractTokens) {
			if (token.getBinaries() != null) {
				tokenDtos.add(new TokenDTO(token));
			}
		}
		return tokenDtos;
	}

	private CertificateToken getCertificate(MultipartFile file) {
		try {
			if (file != null && !file.isEmpty()) {
				return DSSUtils.loadCertificate(file.getBytes());
			}
		} catch (DSSException | IOException e) {
			logger.error("Cannot convert file to X509 Certificate", e);
			logger.error("Unsupported certificate format for file '" + file.getOriginalFilename() + "'");
		}
		return null;
	}

	private void validateAndFillData(CertificateVerifier certVerifier) {
		crtVerifier = certVerifier;
		crtVerifier.setIncludeCertificateRevocationValues(true);
		crtVerifier.setIncludeCertificateTokenValues(true);
		validator = CertificateValidator.fromCertificate(token);
		validator.setCertificateVerifier(crtVerifier);
		certificateReports = validator.validate();
	}
}
