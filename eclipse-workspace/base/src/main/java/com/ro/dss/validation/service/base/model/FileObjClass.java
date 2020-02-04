package com.ro.dss.validation.service.base.model;

import org.springframework.web.multipart.MultipartFile;

public class FileObjClass {
	private MultipartFile originalFile;
	private MultipartFile signedFile;
	private String originalFileName;
	private String signedFileName;
	private String tsa;
	
	public MultipartFile getOriginalFile() {
		return originalFile;
	}
	public void setOriginalFile(MultipartFile originalFile) {
		this.originalFile = originalFile;
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
