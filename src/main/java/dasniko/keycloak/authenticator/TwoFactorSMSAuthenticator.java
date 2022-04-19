package dasniko.keycloak.authenticator;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import dasniko.keycloak.authenticator.gateway.SmsServiceFactory;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.models.*;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;
import org.keycloak.util.JsonSerialization;

import javax.ws.rs.core.Response;
import java.util.Locale;


@JsonIgnoreProperties(value = { "required" })
class TwoFactorAuthAttribute {
	String type;

	public void setType(String type) {
		this.type = type;
	}

	public boolean isSmsType() {
		return type.equals("sms");
	}

	public boolean isAppType() {
		return type.equals("app");
	}
}

/**
 * @author Niko Köbler, https://www.n-k.de, @dasniko
 * @author Claudiu Nicola, https://claudiunicola.xyz, @claudiunicolaa
 */
public class TwoFactorSMSAuthenticator implements Authenticator {

	private static final String TPL_CODE = "login-sms.ftl";

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		AuthenticatorConfigModel config = context.getAuthenticatorConfig();
		KeycloakSession session = context.getSession();
		UserModel user = context.getUser();
		String twoFactorAuthAttr = user.getFirstAttribute("two_factor_auth");

		// skip if the attribute doesn't exist
		if (twoFactorAuthAttr == null) {
			context.success();
			return;
		}
		try {
			TwoFactorAuthAttribute twoFactorAuth =  JsonSerialization.readValue(twoFactorAuthAttr, TwoFactorAuthAttribute.class);
			if (twoFactorAuth.isSmsType()) {
				// type sms -> SMS code needed for authentication
				smsAuth(context, user, config, session);
				return;
			}

			// set current execution as successfully
			context.success();
		} catch (Exception e) {
			throw new RuntimeException(e);
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
				Response errorPage = context.form()
					.setAttribute("realm", context.getRealm())
					.setAttribute("phone", "")
					.setError("smsAuthCodeInvalid")
					.createForm(TPL_CODE);
				context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, errorPage);
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
		return true;
	}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
	}

	@Override
	public void close() {
	}

	private void smsAuth(
		AuthenticationFlowContext context,
		UserModel user,
		AuthenticatorConfigModel config,
		KeycloakSession session
	) {
		String phone = user.getFirstAttribute("phone");
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
			String smsAuthTextMessage = theme.getMessages(locale).getProperty("smsAuthTextMessage");
			String smsText = String.format(smsAuthTextMessage, code, Math.floorDiv(ttl, 60));

			SmsServiceFactory.get(config.getConfig()).send(phone, smsText);

			Response challengePage = context.form()
				.setAttribute("realm", context.getRealm())
				.setAttribute("phone", anonymisePhone(phone))
				.createForm(TPL_CODE);
			context.challenge(challengePage);
		} catch (Exception e) {
			Response errorPage = context.form()
				.setError("smsAuthSmsNotSent", e.getMessage())
				.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR);
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, errorPage);
		}
	}

	private String anonymisePhone(String phone) {
		String lastThreePhoneDigits = phone.substring(phone.length() - 3);
		return "*".repeat(phone.length() - 3) + lastThreePhoneDigits;
	}
}
