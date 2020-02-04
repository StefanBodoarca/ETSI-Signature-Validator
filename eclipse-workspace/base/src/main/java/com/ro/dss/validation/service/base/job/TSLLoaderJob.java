package com.ro.dss.validation.service.base.job;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import eu.europa.esig.dss.tsl.service.TSLValidationJob;

@Service
public class TSLLoaderJob {

	@Value("${cron.tl.loader.enable}")
	private boolean enable;

	@Autowired
	private TSLValidationJob job;
	
	@PostConstruct
	public void init() {
		System.out.println("In init job");
		job.initRepository();
	}

	@Scheduled(initialDelayString = "${cron.initial.delay.tl.loader}", fixedDelayString = "${cron.delay.tl.loader}")
	public void refresh() {
		System.out.println("In refresh job");
		if (enable) {
			job.refresh();
		}
	}
}
