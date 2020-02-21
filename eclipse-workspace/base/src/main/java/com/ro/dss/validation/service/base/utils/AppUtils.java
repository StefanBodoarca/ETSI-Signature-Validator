package com.ro.dss.validation.service.base.utils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.web.multipart.MultipartFile;

import com.ro.dss.validation.service.base.model.TokenDTO;

import eu.europa.esig.dss.diagnostic.AbstractTokenProxy;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

public final class AppUtils {
	private AppUtils() {
	}

	public static DSSDocument toDSSDocument(MultipartFile multipartFile) {
		try {
			if ((multipartFile != null) && !multipartFile.isEmpty()) {
				DSSDocument document = new InMemoryDocument(multipartFile.getBytes(), multipartFile.getOriginalFilename());
				return document;
			}
		} catch (IOException e) {
			//logger.error("Cannot read  file : " + e.getMessage(), e);
			e.printStackTrace();
		}
		return null;
	}

	public static List<DSSDocument> toDSSDocuments(List<MultipartFile> documentsToSign) {
		List<DSSDocument> dssDocuments = new ArrayList<DSSDocument>();
		for (MultipartFile multipartFile : documentsToSign) {
			DSSDocument dssDocument = toDSSDocument(multipartFile);
			if (dssDocument != null) {
				dssDocuments.add(dssDocument);
			}
		}
		return dssDocuments;
	}
	
	public static DSSDocument toDSSDocument(String b64File, String name) {
		if ((b64File != null) && name != null) {
			DSSDocument document = new InMemoryDocument(b64File.getBytes(), name);
			return document;
		}
		return null;
	}
	
	public static Set<TokenDTO> buildTokenDtos(Set<? extends AbstractTokenProxy> abstractTokens) {
		Set<TokenDTO> tokenDtos = new HashSet<TokenDTO>();
		for (AbstractTokenProxy token : abstractTokens) {
			if (token.getBinaries() != null) {
				tokenDtos.add(new TokenDTO(token));
			}
		}
		return tokenDtos;
	}
}
