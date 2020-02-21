package com.ro.dss.validation.service.base.controller;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.json.JSONArray;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.ro.dss.validation.service.base.model.CertificateDTO;
import com.ro.dss.validation.service.base.serviceclass.KeystoreService;

import eu.europa.esig.dss.spi.tsl.TLInfo;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.tsl.TSLParserResult;
import eu.europa.esig.dss.tsl.TSLServiceProvider;
import eu.europa.esig.dss.tsl.TSLValidationModel;
import eu.europa.esig.dss.tsl.service.TSLRepository;
import eu.europa.esig.dss.utils.Utils;

@RestController
public class TrustedListController {
	
	private static final String CERTIFICATE_TILE = "trusted-certificates-from-keystore";

	@Autowired
	private KeystoreService keystoreService;
	
	@Autowired
	private TSLRepository tslRepository;

	@Autowired
	private KeyStoreCertificateSource trustStore;

	@RequestMapping(value = "/tsl-info")
	public ResponseEntity<Object> getTslInfo() {
		Map<String, TLInfo> mapObj = tslRepository.getSummary();
		//return new ResponseEntity<>(tslRepository.getActualOjUrl(), HttpStatus.OK);
		return new ResponseEntity<>(tslRepository.getSummary(), HttpStatus.OK);
	}
	
	@RequestMapping(value = "/tsl-info/{country:[a-z][a-z]}", method = RequestMethod.GET)
	public ResponseEntity<Object> getByCountry(@PathVariable String country) {
		String countryUppercase = Utils.upperCase(country);
		Set<String> keySet = tslRepository.getAllMapTSLValidationModels().keySet();
		TSLValidationModel model = tslRepository.getByCountry(countryUppercase);
		TSLParserResult parserResult = model.getParseResult();
		List<TSLServiceProvider> tslServiceProdersList = parserResult.getServiceProviders();
		String result = "Electronic Address; Name; PostalAddress; Registration Identifier\n\r";
		for(int i = 0; i < tslServiceProdersList.size(); i++) {
			result += " "  + tslServiceProdersList.get(i).getElectronicAddress() + "; ";
			result += " "  + tslServiceProdersList.get(i).getName() + "; ";
			result += " "  + tslServiceProdersList.get(i).getPostalAddress() + "; ";
			result += " "  + tslServiceProdersList.get(i).getRegistrationIdentifier() + "; ";
			result += "\n\r";
		}
		return new ResponseEntity<>(result, HttpStatus.OK);
	}
	
	@RequestMapping(value = "/trust-certificates-info")
	public ResponseEntity<Object> getTrustCertificatesInfo() {
		List<CertificateDTO> certList = keystoreService.getCertificatesDTOFromKeyStore();
		return new ResponseEntity<>(certList, HttpStatus.OK);
	}
}
