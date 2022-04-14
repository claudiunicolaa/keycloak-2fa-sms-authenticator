package dasniko.keycloak.authenticator;

import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class UpdatePhoneRequiredActionFactory implements RequiredActionFactory {
	@Override
	public String getDisplayText() {
		return "Update Phone";
	}

	@Override
	public RequiredActionProvider create(KeycloakSession session) {
		return new UpdatePhoneRequiredAction();
	}

	@Override
	public void init(Config.Scope config) {

	}

	@Override
	public void postInit(KeycloakSessionFactory factory) {

	}

	@Override
	public void close() {

	}

	@Override
	public String getId() {
		return "update-phone-required-action";
	}
}
