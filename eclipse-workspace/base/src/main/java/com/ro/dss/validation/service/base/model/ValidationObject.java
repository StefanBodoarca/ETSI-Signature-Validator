package com.ro.dss.validation.service.base.model;

public class ValidationObject {
	private String originalDocument;
	private String originalDocumentName;
	private String signedDocument;
	private String signedDocumentName;
	
	public ValidationObject() {}

	public String getOriginalDocument() {
		return originalDocument;
	}

	public void setOriginalDocument(String originalDocument) {
		this.originalDocument = originalDocument;
	}

	public String getOriginalDocumentName() {
		return originalDocumentName;
	}

	public void setOriginalDocumentName(String originalDocumentName) {
		this.originalDocumentName = originalDocumentName;
	}

	public String getSignedDocument() {
		return signedDocument;
	}

	public void setSignedDocument(String signedDocument) {
		this.signedDocument = signedDocument;
	}

	public String getSignedDocumentName() {
		return signedDocumentName;
	}

	public void setSignedDocumentName(String signedDocumentName) {
		this.signedDocumentName = signedDocumentName;
	}
}
