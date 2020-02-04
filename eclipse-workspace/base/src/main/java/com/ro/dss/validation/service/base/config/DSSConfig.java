package com.ro.dss.validation.service.base.config;

import java.io.IOException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import javax.annotation.PostConstruct;
import javax.sql.DataSource;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.ClassPathResource;

import com.ro.dss.validation.service.base.controller.CertificateController;
import com.ro.dss.validation.service.base.custom.COfflineCRLSource;
import com.ro.dss.validation.service.base.custom.CSignatureCRLSource;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.crl.JdbcCacheCRLSource;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.ExternalResourcesCRLSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.OfflineCRLSource;
import eu.europa.esig.dss.tsl.OtherTrustedList;
import eu.europa.esig.dss.tsl.service.TSLRepository;
import eu.europa.esig.dss.tsl.service.TSLValidationJob;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.ListCRLSource;
import eu.europa.esig.dss.validation.SignatureCRLSource;

@Configuration
@Import(PersistenceConfig.class)
public class DSSConfig {
	private static final Logger LOG = Logger.getLogger(CertificateController.class.getName());

	@Value("${content.keystore.type}")
	private String ksType;

	@Value("${content.keystore.filename}")
	private String ksFilename;

	@Value("${content.keystore.password}")
	private String ksPassword;
	
	@Value("${default.validation.policy}")
	private String defaultValidationPolicy;
	
	@Value("${crl.url.source}")
	private String crlURL;
	
	@Value("${crl.offline.path.source}")
	private String crlOfflinePath;
	
	@Autowired
	private DataSource dataSource;
	
	private byte[] CRL_LIST = null;
	
	@PostConstruct
	public void fillCrlList() {
		LOG.info("in @postconstruct - checkCRL");
		CRL_LIST = dataLoader().get(crlURL);
		LOG.info(CRL_LIST.length);
		LOG.info(CRL_LIST);
	}

	@Bean
	public KeyStoreCertificateSource trustStore() throws IOException {
		return new KeyStoreCertificateSource(new ClassPathResource(ksFilename).getFile(), ksType, ksPassword);
	}
	
	@Bean
	public TrustedListsCertificateSource trustedListSource() throws IOException {
		KeyStoreCertificateSource myTrustStore = trustStore();
		TrustedListsCertificateSource myTrustList = new TrustedListsCertificateSource();
		List<CertificateToken> crtsList = myTrustStore.getCertificates();
		for(CertificateToken crtToken : crtsList) {
			myTrustList.addCertificate(crtToken, null);
		}
		return myTrustList;
	}
	
	@Bean
	public CertificateVerifier certificateVerifier() throws Exception {
		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		//certificateVerifier.setTrustedCertSource(trustStore());
		certificateVerifier.setTrustedCertSource(trustedListSource());
		//certificateVerifier.setCrlSource(cachedCRLSource());
		certificateVerifier.setCrlSource(cofflineCRLSource());
		//certificateVerifier.setSignatureCRLSource(listCRLSource());
		//certificateVerifier.setCrlSource(offlineCRLSource());
		certificateVerifier.setDataLoader(dataLoader());

		// Default configs
		certificateVerifier.setExceptionOnMissingRevocationData(true);
		certificateVerifier.setCheckRevocationForUntrustedChains(false);
		return certificateVerifier;
	}

	@Bean
	public TSLRepository tslRepository() throws IOException {
		TSLRepository tslRepository = new TSLRepository();
		tslRepository.setTrustedListsCertificateSource(trustedListSource());
		return tslRepository;
	}

	@Bean
	public OtherTrustedList otherTrustedList() throws IOException {
		OtherTrustedList otherTrustedList = new OtherTrustedList();
		otherTrustedList.setTrustStore(trustStore());
		return otherTrustedList;
	}

	@Bean
	public TSLValidationJob tslValidationJob() throws IOException {
		TSLValidationJob validationJob = new TSLValidationJob();
		validationJob.setRepository(tslRepository());
		validationJob.refresh();
		return validationJob;
	}
	
	@Bean
	public CommonsDataLoader dataLoader() {
		LOG.info("start data loader");
		CommonsDataLoader dataLoader = new CommonsDataLoader();
		dataLoader.get(crlURL, true);
		return dataLoader;
	}
	
	@Bean 
	public OnlineCRLSource onlineCRLSource() {
		OnlineCRLSource onlineCRLSource = new OnlineCRLSource();
		onlineCRLSource.setDataLoader(dataLoader());
		return onlineCRLSource;
	}
	
	@Bean
	public COfflineCRLSource cofflineCRLSource() {
		COfflineCRLSource cofflineCRLSource = new COfflineCRLSource();
		cofflineCRLSource.addCRL(CRL_LIST, RevocationOrigin.EXTERNAL);
		return cofflineCRLSource;
	}
	
	@Bean
	public ListCRLSource listCRLSource() {
		ListCRLSource listCRLSource = new ListCRLSource(cofflineCRLSource());
		return listCRLSource;
	}
	
	@Bean
	public OfflineCRLSource offlineCRLSource() {
		OfflineCRLSource offlineCRLSource = null;
		return offlineCRLSource;
	}
	
	@Bean
	public JdbcCacheCRLSource cachedCRLSource() {
		JdbcCacheCRLSource jdbcCacheCRLSource = new JdbcCacheCRLSource();
		jdbcCacheCRLSource.setDataSource(dataSource);
		jdbcCacheCRLSource.setProxySource(onlineCRLSource());
		jdbcCacheCRLSource.setDefaultNextUpdateDelay((long) (60 * 3)); // 3 minutes
		return jdbcCacheCRLSource;
	}
	
	@PostConstruct
	public void cachedCRLSourceInitialization() throws SQLException {
		JdbcCacheCRLSource jdbcCacheCRLSource = cachedCRLSource();
		jdbcCacheCRLSource.initTable();
	}
	
	@Bean
	public byte[] getCRLList() {
		return CRL_LIST;
	}
}
