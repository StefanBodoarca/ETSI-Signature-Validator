package com.ro.dss.validation.service.base.model;

import org.springframework.web.multipart.MultipartFile;

public class CrtClassMultipartFile {
	private MultipartFile crtFile;

	public MultipartFile getCrtFile() {
		return crtFile;
	}

	public void setCrtFile(MultipartFile crtFile) {
		this.crtFile = crtFile;
	}
}
