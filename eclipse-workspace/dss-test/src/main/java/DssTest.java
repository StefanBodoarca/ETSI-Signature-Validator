import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import eu.europa.esig.dss.token.MSCAPISignatureToken;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import java.util.List;

public class DssTest {
	private static XAdESSignatureParameters parameters = new XAdESSignatureParameters();
	static {
		@SuppressWarnings("resource")
		MSCAPISignatureToken signingToken = new MSCAPISignatureToken();
		List<DSSPrivateKeyEntry> list = signingToken.getKeys();
		System.out.println(list.size());
		DSSPrivateKeyEntry privateKey = list.get(0);
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		// We choose the type of the signature packaging (ENVELOPED, ENVELOPING, DETACHED).
		parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		// We set the digest algorithm to use with the signature algorithm. You must use the
		// same parameter when you invoke the method sign on the token. The default value is SHA256
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

		// We set the signing certificate
		parameters.setSigningCertificate(privateKey.getCertificate());
		// We set the certificate chain
		parameters.setCertificateChain(privateKey.getCertificateChain());

		// Create common certificate verifier
		CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();

		// Create XAdES service for signature
		XAdESService service = new XAdESService(commonCertificateVerifier);

		DSSDocument toSignDocument = new FileDocument("src/main/resources/xml_example.xml");
		// Get the SignedInfo XML segment that need to be signed.
		ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);

		// This function obtains the signature value for signed information using the
		// private key and specified algorithm
		SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);
		
		// We invoke the xadesService to sign the document with the signature value obtained in
		// the previous step.
		DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

		// save the signed document on the filesystem
		try {
			signedDocument.save("target/signedXmlXadesMSCapi.xml");
		} catch(Exception e) {
			e.printStackTrace();
		}
		
	}
}
