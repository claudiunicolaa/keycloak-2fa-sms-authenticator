package dasniko.keycloak.authenticator;

import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;

import java.util.Collections;

public class UpdatePhoneRequiredAction implements RequiredActionProvider {

	private static final String TPL_CODE = "update-phone.ftl";

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
		String enteredPhone = context.getHttpRequest().getDecodedFormParameters().getFirst("phone");
		// phone of course has to be further validated on proper format, country code, ... @todo!
		if (enteredPhone == null) {
			context.failure();
			return;
		}
		context.getUser().setAttribute("phone", Collections.singletonList(enteredPhone));
		context.success();
	}

	@Override
	public void close() {

	}
}
