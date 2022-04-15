<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=true; section>
	<#if section = "header">
		${msg("phoneAuthTitle",realm.displayName)}
	<#elseif section = "show-username">
		<div class="${properties.kcFormGroupClass!}">
    		<div id="kc-username">
    			<label id="kc-attempted-username">${msg("phoneAuthTitle")}</label>
    			<a id="reset-login" href="${url.loginRestartFlowUrl}">
    				<div class="kc-login-tooltip">
									<i class="${properties.kcResetFlowIcon!}"></i>
    					<span class="kc-tooltip-text">${msg("restartLoginTooltip")}</span>
    				</div>
    			</a>
    		</div>
    	</div>
	<#elseif section = "form">
		<form id="kc-sms-code-login-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
			<div class="${properties.kcFormGroupClass!}">
				<div class="${properties.kcLabelWrapperClass!}">
					<label for="phone" class="${properties.kcLabelClass!}">${msg("phoneAuthLabel")}</label>
				</div>
				<div class="${properties.kcInputWrapperClass!}">
					<input type="text" id="phone" name="phone" class="${properties.kcInputClass!}" value="${(phone)!''}" autofocus/>
				</div>
			</div>
			<div class="${properties.kcFormGroupClass!} ${properties.kcFormSettingClass!}">
				<div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
					<input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}" type="submit" value="${msg("doSubmit")}"/>
				</div>
			</div>
		</form>
	<#elseif section = "info" >
		${msg("smsAuthInstruction")}
	</#if>
</@layout.registrationLayout>
