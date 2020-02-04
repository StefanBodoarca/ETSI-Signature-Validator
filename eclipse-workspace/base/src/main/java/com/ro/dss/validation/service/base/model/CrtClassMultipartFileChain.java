package com.ro.dss.validation.service.base.model;

import java.util.List;

import org.springframework.web.multipart.MultipartFile;

public class CrtClassMultipartFileChain {
	private MultipartFile crtFile;
	private List<MultipartFile> crtChainFiles;

	public MultipartFile getCrtFile() {
		return crtFile;
	}

	public void setCrtFile(MultipartFile crtFile) {
		this.crtFile = crtFile;
	}

	public List<MultipartFile> getCrtChainFiles() {
		return crtChainFiles;
	}

	public void setCrtChainFiles(List<MultipartFile> crtChainFiles) {
		this.crtChainFiles = crtChainFiles;
	}
	
	
}
