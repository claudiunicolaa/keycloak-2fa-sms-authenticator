package dasniko.keycloak.authenticator;

import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.google.i18n.phonenumbers.Phonenumber;

import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.sessions.AuthenticationSessionModel;

import javax.ws.rs.core.Response;
import java.util.Collections;

public class UpdatePhoneRequiredAction implements RequiredActionProvider {

	private static final String TPL_CODE = "login-update-phone.ftl";

	@Override
	public void evaluateTriggers(RequiredActionContext context) {

	}

	@Override
	public void requiredActionChallenge(RequiredActionContext context) {
		context.challenge(
			context.form()
				.setAttribute("realm", context.getRealm())
				.createForm(TPL_CODE)
		);
	}

	@Override
	public void processAction(RequiredActionContext context) {
		EventBuilder event = context.getEvent()
			.event(EventType.UPDATE_PROFILE)
			.detail(Details.REASON, "update-phone");
		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		EventBuilder errorEvent = event.clone().event(EventType.UPDATE_PROFILE_ERROR)
			.client(authSession.getClient())
			.user(authSession.getAuthenticatedUser());
		String enteredPhone = context.getHttpRequest().getDecodedFormParameters().getFirst("phone");

		if (enteredPhone == null || !isValidPhone(enteredPhone)) {
			Response challenge = context.form()
				.setAttribute("phone", enteredPhone)
				.addError(new FormMessage("phone", "phoneAuthInvalid"))
				.createForm(TPL_CODE);
			context.challenge(challenge);
			errorEvent.error("invalid_phone");
			return;
		}

		context.getUser().setAttribute("phone", Collections.singletonList(enteredPhone));
		context.success();
	}

	@Override
	public void close() {

	}

	private boolean isValidPhone(String phone) {
		Phonenumber.PhoneNumber phoneProto;
		try {
			phoneProto = PhoneNumberUtil.getInstance().parse(phone, null);
		} catch (NumberParseException e) {
			return false;
		}
		return PhoneNumberUtil.getInstance().isValidNumber(phoneProto);
	}
}
