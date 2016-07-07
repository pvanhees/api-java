package com.nauth.api;

import org.apache.http.client.methods.*;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import javax.net.ssl.*;
import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.util.*;

/**
 * Simple HTTP client wrapper. This one uses the Apache HTTP Client.
 */
public class NAuthBackend {
	protected boolean useSSL;
	private SSLConnectionSocketFactory sslsf;

	public static final String DEFAULT_PK = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuJlaS3XZdRpcT/uek5nxX4iqn/7As1BY2VACO8wSM3m7VG6iN/Py2jTguIfVJcQhtk1sy7elG0AXDKO3peWc+of4pHTpQ9kaFcvFisi6uDcDWAIJMjiSE2iAm8veZ+5LddqDD/iItRYul4mFsKIl8Q6DKBvKkHjn3tXC2g3bvvsY689qbH7FhKpueGx8Z+yKvV209FGSkFKI+sGOB/C4OeF/KX3FTw/gMMD0YrS2skV+lg3jGTNzNep7Gfhuz4j4CrKXx67p7x3EV8m2kDDIQMwWi/rxSJ2V/0sKbUebnsozUDpWi1blRJjtSW27tFVxrffXWrpw4O5HxEcMtB65RQIDAQAB";

	public static final List<String> DEFAULT_CIPHERS = Arrays.asList(
			"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA",
			"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA",
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA",
			"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
			"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
			"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
			"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");

	/**
	 * Construct new backend without SSL
	 */
	public NAuthBackend() {
		this.useSSL = false;
	}

	/**
	 * Construct new backend with TLS. Only TLSv1.2 is supported.
	 * 
	 * @param pk
	 *            Public key of the certificate to pin (certificate pinning). If
	 *            pk is null, the public key of the n-Auth demo server is set.
	 * @param ciphers
	 *            List of ciphers to support. If ciphers is null, a default list
	 *            is used. (All matching the following pattern: TLS_ECDHE_{RSA |
	 *            ECDSA}_WITH_AES_{128 | 256}_{GCM | CBC}_SHA )
	 * 
	 */
	public NAuthBackend(String pk, List<String> ciphers)
			throws NAuthServerException {
		this.useSSL = true;

		setupSSLContext((pk == null) ? DEFAULT_PK : pk,
				(ciphers == null) ? DEFAULT_CIPHERS : ciphers);
	}

	private void setupSSLContext(final String pk, final List<String> cipherList)
			throws NAuthServerException {
		try {
			SSLContext ctx = SSLContext.getInstance("TLSv1.2");
			ctx.init(null, null, null);

			SSLParameters params = ctx.getDefaultSSLParameters();

			ArrayList<String> ciphers = new ArrayList<String>(
					Arrays.asList(params.getCipherSuites()));
			ciphers.retainAll(cipherList);

			sslsf = new SSLConnectionSocketFactory(ctx,
					new String[] { "TLSv1.2" },
					ciphers.toArray(new String[ciphers.size()]),
					new HostnameVerifier() {

						@Override
						public boolean verify(String hostname,
								SSLSession session) {
							try {
								Certificate cert = session
										.getPeerCertificates()[0];
								return pk.equals(Base64.getEncoder()
										.encodeToString(
												cert.getPublicKey()
														.getEncoded()));
							} catch (SSLPeerUnverifiedException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
								return false;
							}

						}
					});

		} catch (NoSuchAlgorithmException e) {
			throw new NAuthServerException(e);
		} catch (KeyManagementException e) {
			throw new NAuthServerException(e);
		}
	}

	private CloseableHttpClient getHttpClient() {
		if (useSSL)
			return HttpClients.custom().setSSLSocketFactory(sslsf).build();
		else
			return HttpClients.createDefault();
	}

	public byte[] getHttpAsBytes(String method, String uri, String[] action,
			Map<String, String> params, Map<String, String> headers)
			throws NAuthServerException {
		CloseableHttpClient httpClient = getHttpClient();
		try {
			URI fulluri = getUri(uri, action, params);

			final HttpUriRequest request = getRequestByMethod(method, fulluri);
			for (Map.Entry<String, String> header : headers.entrySet()) {
				request.setHeader(header.getKey(), header.getValue());
			}

			CloseableHttpResponse response = httpClient.execute(request);
			processStatusCode(response);
			try {
				InputStream i = response.getEntity().getContent();

				try {
					return readInputStreamAsBytes(i);
				} finally {
					i.close();
				}

			} finally {
				response.close();
			}

		} catch (IOException e) {
			throw new NAuthServerException(e);
		} finally {
			try {
				httpClient.close();
			} catch (IOException e) {
			}
		}
	}

	private static String readInputStream(InputStream inputStream)
			throws IOException {

		StringBuilder textBuilder = new StringBuilder();
		try (Reader reader = new BufferedReader(new InputStreamReader(
				inputStream, Charset.forName(StandardCharsets.UTF_8.name())))) {
			int c = 0;
			while ((c = reader.read()) != -1) {
				textBuilder.append((char) c);
			}
		}
		return textBuilder.toString();
	}

	private static byte[] readInputStreamAsBytes(InputStream is)
			throws IOException {
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();

		int nRead;
		byte[] data = new byte[16384];

		while ((nRead = is.read(data, 0, data.length)) != -1) {
			buffer.write(data, 0, nRead);
		}

		buffer.flush();

		return buffer.toByteArray();
	}

	private URI getUri(String uri, String[] action, Map<String, String> params)
			throws NAuthServerException {
		URIBuilder builder;
		try {
			String fulluri = uri + "/";
			for (String part : action) {
				try {
					fulluri += URLEncoder.encode(part, "UTF-8") + "/";
				} catch (UnsupportedEncodingException e) {
					throw new NAuthServerException(e);
				}
			}
			builder = new URIBuilder(fulluri);
			if (params != null) {
				for (Map.Entry<String, String> entry : params.entrySet()) {
					builder.addParameter(entry.getKey(), entry.getValue());
				}
			}
			URI ret = builder.build();
			// System.out.println(ret);
			return ret;
		} catch (URISyntaxException e) {
			throw new NAuthServerException(e);
		}

	}

	private HttpUriRequest getRequestByMethod(String method, URI uri) {
		switch (method) {
		case "GET":
		default:
			return new HttpGet(uri);
		case "POST":
			return new HttpPost(uri);
		case "DELETE":
			return new HttpDelete(uri);
		case "PUT":
			return new HttpPut(uri);
		case "OPTIONS":
			return new HttpOptions(uri);
		}
	}

	public String getHttpAsString(String method, String uri, String[] action,
			Map<String, String> params, Map<String, String> headers)
			throws NAuthServerException {
		CloseableHttpClient httpClient = getHttpClient();
		try {
			URI fulluri = getUri(uri, action, params);

			final HttpUriRequest request = getRequestByMethod(method, fulluri);
			for (Map.Entry<String, String> header : headers.entrySet()) {
				request.setHeader(header.getKey(), header.getValue());
			}

			CloseableHttpResponse response = httpClient.execute(request);
			processStatusCode(response);
			try {
				InputStream i = response.getEntity().getContent();

				try {
					return readInputStream(i);
				} finally {
					i.close();
				}

			} finally {
				response.close();
			}

		} catch (IOException e) {
			throw new NAuthServerException(e);
		} finally {
			try {
				httpClient.close();
			} catch (IOException e) {
			}
		}
	}

	private void processStatusCode(CloseableHttpResponse response) throws NAuthServerException {
		int code = response.getStatusLine().getStatusCode();
		
		/* success codes - 2xx */
		if(code >= 200 && code < 300)
			return;
		
		/* other codes */
		throw new NAuthServerException("HTTP response "+code + " "+response.getStatusLine().getReasonPhrase());
	}
	
}
