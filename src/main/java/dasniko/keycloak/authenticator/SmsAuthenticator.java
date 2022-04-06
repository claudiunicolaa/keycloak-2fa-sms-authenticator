package dasniko.keycloak.authenticator;

import dasniko.keycloak.authenticator.gateway.SmsServiceFactory;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;
import org.keycloak.util.JsonSerialization;

import javax.json.Json;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;


class TwoFactorAuthAttribute {
	Boolean required;
	String set;

	public Boolean getRequired() {
		return required;
	}

	public void setRequired(Boolean required) {
		this.required = required;
	}

	public String getSet() {
		return set;
	}

	public void setSet(String set) {
		this.set = set;
	}
}

/**
 * @author Niko Köbler, https://www.n-k.de, @dasniko
 * @author Claudiu Nicola, https://claudiunicola.xyz, @claudiunicolaa
 */
public class SmsAuthenticator implements Authenticator {

	private static final String TPL_CODE = "login-sms.ftl";

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		AuthenticatorConfigModel config = context.getAuthenticatorConfig();
		KeycloakSession session = context.getSession();
		UserModel user = context.getUser();
		String twoFactorAuthAttr = user.getFirstAttribute("two_factor_auth");

		// skip if the attribute doesn't exists
		if (twoFactorAuthAttr == null) {
			context.success();
			return;
		}
		try {
			TwoFactorAuthAttribute twoFactorAuth =  JsonSerialization.readValue(twoFactorAuthAttr, TwoFactorAuthAttribute.class);
			if (Objects.equals(twoFactorAuth.getSet(), "sms")) {
				String mobileNumber = user.getFirstAttribute("phone");
				// phone of course has to be further validated on proper format, country code, ... @todo!

				int length = Integer.parseInt(config.getConfig().get("length"));
				int ttl = Integer.parseInt(config.getConfig().get("ttl"));

				String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
				AuthenticationSessionModel authSession = context.getAuthenticationSession();
				authSession.setAuthNote("code", code);
				authSession.setAuthNote("ttl", Long.toString(System.currentTimeMillis() + (ttl * 1000L)));

				try {
					Theme theme = session.theme().getTheme(Theme.Type.LOGIN);
					Locale locale = session.getContext().resolveLocale(user);
					String smsAuthText = theme.getMessages(locale).getProperty("smsAuthText");
					String smsText = String.format(smsAuthText, code, Math.floorDiv(ttl, 60));

					SmsServiceFactory.get(config.getConfig()).send(mobileNumber, smsText);

					context.challenge(context.form().setAttribute("realm", context.getRealm()).createForm(TPL_CODE));
				} catch (Exception e) {
					context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
						context.form().setError("smsAuthSmsNotSent", e.getMessage())
							.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
				}
			}
		} catch (IOException ioe) {
			throw new RuntimeException(ioe);
		}
	}

	@Override
	public void action(AuthenticationFlowContext context) {
		String enteredCode = context.getHttpRequest().getDecodedFormParameters().getFirst("code");

		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		String code = authSession.getAuthNote("code");
		String ttl = authSession.getAuthNote("ttl");

		if (code == null || ttl == null) {
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
				context.form().createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
			return;
		}

		boolean isValid = enteredCode.equals(code);
		if (isValid) {
			if (Long.parseLong(ttl) < System.currentTimeMillis()) {
				// expired
				context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
					context.form().setError("smsAuthCodeExpired").createErrorPage(Response.Status.BAD_REQUEST));
			} else {
				// valid
				context.success();
			}
		} else {
			// invalid
			AuthenticationExecutionModel execution = context.getExecution();
			if (execution.isRequired()) {
				context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
					context.form().setAttribute("realm", context.getRealm())
						.setError("smsAuthCodeInvalid").createForm(TPL_CODE));
			} else if (execution.isConditional() || execution.isAlternative()) {
				context.attempted();
			}
		}
	}

	@Override
	public boolean requiresUser() {
		return true;
	}

	@Override
	public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
		return user.getFirstAttribute("phone") != null;
	}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
	}

	@Override
	public void close() {
	}

}
