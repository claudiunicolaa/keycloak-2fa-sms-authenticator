package dasniko.keycloak.authenticator.gateway;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;


import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.Map;


class SmsSendFailsException extends Exception {
}

/**
 * @author Claudiu Nicola, https://claudiunicola.xyz, @claudiunicolaa
 */
public class InhouseSmsService implements SmsService {

	private static final Logger LOG = Logger.getLogger(InhouseSmsService.class);

	private final String senderId;
	private final String apiKey;
	private final URI uri;
	private final HttpClient httpClient;

	InhouseSmsService(Map<String, String> config) {
		senderId = config.get("senderId");
		uri = URI.create(config.get("uri"));
		apiKey = config.get("apiKey");
		httpClient = HttpClient.newHttpClient();
	}

	@Override
	public void send(String phoneNumber, String message) {
		try {
			HttpRequest request = buildHttpRequest(phoneNumber, message);
			HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

			if (response.statusCode() != 201) {
				throw new SmsSendFailsException();
			}
			LOG.info(String.format("SMS OTP sent. %s", response.body()));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private HttpRequest buildHttpRequest(String phoneNumber, String message) throws JsonProcessingException {
		var values = new HashMap<String, String>() {{
			put("from", senderId);
			put("to", phoneNumber);
			put("text", message);
		}};
		var objectMapper = new ObjectMapper();
		String requestBody = objectMapper
			.writeValueAsString(values);

		return HttpRequest
			.newBuilder()
			.uri(uri)
			.setHeader("X-Api-Key", apiKey)
			.setHeader("User-Agent", "Keycloak HttpClient")
			.setHeader("Content-Type", "application/json")
			.POST(HttpRequest.BodyPublishers.ofString(requestBody))
			.build();
	}
}
