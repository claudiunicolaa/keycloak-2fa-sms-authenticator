package dasniko.keycloak.authenticator.gateway;

import io.github.cdimascio.dotenv.Dotenv;

import java.util.HashMap;
import java.util.Map;

// Notice: this will make a real HTTP request to the in-house configured SMS gateway.
class InhouseSmsServiceIntegrationTest {
	@org.junit.jupiter.api.Test
	void send() {
		Dotenv dotenv = Dotenv.load();
		String uri = dotenv.get("URI");
		String apiKey = dotenv.get("API_KEY");
		String phoneNumber = dotenv.get("PHONE_NUMBER");

		Map<String, String> config = new HashMap<>() {{
			put("senderId", "AutoTest");
			put("uri", uri);
			put("apiKey", apiKey);
		}};
		InhouseSmsService service = new InhouseSmsService(config);
		service.send(phoneNumber, "Integration Test.");
	}
}
