package com.ro.dss.validation.service.base.model;

import java.util.List;

public class CrtCalssBase64Chain {
	private String base64CrtFile;
	private List<String> base64ChainFiles;

	public String getBase64CrtFile() {
		return base64CrtFile;
	}

	public void setBase64CrtFile(String base64CrtFile) {
		this.base64CrtFile = base64CrtFile;
	}

	public List<String> getBase64ChainFiles() {
		return base64ChainFiles;
	}

	public void setBase64ChainFiles(List<String> base64ChainFiles) {
		this.base64ChainFiles = base64ChainFiles;
	}
	
	
}
