package com.ro.dss.validation.service.base.controller;

import java.util.List;

import org.json.JSONArray;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;

@RestController
public class TrustedListController {

	@Autowired
	private KeyStoreCertificateSource trustStore;

	@RequestMapping(value = "/tsl-info")
	public ResponseEntity<Object> getTslInfo() {
		// System.out.println(trustStore.getCertificates().size());
		// System.out.println(trustStore.getCertificates());
		return new ResponseEntity<>(trustStore.getCertificates().toString(), HttpStatus.OK);
	}
}
