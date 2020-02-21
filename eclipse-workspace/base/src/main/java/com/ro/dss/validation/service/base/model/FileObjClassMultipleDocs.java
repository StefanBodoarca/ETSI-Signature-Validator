package com.ro.dss.validation.service.base.model;

import java.util.List;

import org.springframework.web.multipart.MultipartFile;

public class FileObjClassMultipleDocs {
	private List<MultipartFile> originalFiles;
	private MultipartFile signedFile;
	private MultipartFile crtFile;
	private MultipartFile policyFile;
	private String originalFileName;
	private String signedFileName;
	private String validationLevel = null;
	private String tsa = null;
	
	public String getValidationLevel() {
		return validationLevel;
	}
	public void setValidationLevel(String validationLevel) {
		this.validationLevel = validationLevel;
	}
	public MultipartFile getCrtFile() {
		return crtFile;
	}
	public void setCrtFile(MultipartFile crtFile) {
		this.crtFile = crtFile;
	}
	public MultipartFile getPolicyFile() {
		return policyFile;
	}
	public void setPolicyFile(MultipartFile policyFile) {
		this.policyFile = policyFile;
	}
	public List<MultipartFile> getOriginalFiles() {
		return originalFiles;
	}
	public void setOriginalFiles(List<MultipartFile> originalFiles) {
		this.originalFiles = originalFiles;
	}
	public MultipartFile getSignedFile() {
		return signedFile;
	}
	public void setSignedFile(MultipartFile signedFile) {
		this.signedFile = signedFile;
	}
	public String getOriginalFileName() {
		return originalFileName;
	}
	public void setOriginalFileName(String originalFileName) {
		this.originalFileName = originalFileName;
	}
	
	public String getSignedFileName() {
		return signedFileName;
	}
	public void setSignedFileName(String signedFileName) {
		this.signedFileName = signedFileName;
	}
	public String getTsa() {
		return tsa;
	}
	public void setTsa(String tsa) {
		this.tsa = tsa;
	}
}
