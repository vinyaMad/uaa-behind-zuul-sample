package com.kakawait;

import java.net.URL;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.RedirectUrlBuilder;

final class ProxyAwareLogingAuthenticationEntryPoint extends LoginUrlAuthenticationEntryPoint {
	public static final String PROXIED_PREFIX = "x-forwarded-prefix";
	public static final String PROXIED_PROTO = "x-Forwarded-Proto";
	public static final String PROXIED_HOST = "x-forwarded-host";
	public static final String PORT_SEPARATOR = ":";

	ProxyAwareLogingAuthenticationEntryPoint(String loginFormUrl) {
		super(loginFormUrl);
	}

	@Override
	protected String buildRedirectUrlToLoginPage(HttpServletRequest request,
			HttpServletResponse response, AuthenticationException authException) {
		
		if (request.getHeader(PROXIED_HOST) != null) {
			//replace host with forwarded host from proxy
			RedirectUrlBuilder urlBuilder = new RedirectUrlBuilder();
			if (request.getHeader(PROXIED_PROTO) == null) {
				urlBuilder.setScheme(request.getScheme());
			}else {
				urlBuilder.setScheme(request.getHeader(PROXIED_PROTO));
			}
			String fHost = request.getHeader(PROXIED_HOST);
			if (fHost.contains(PORT_SEPARATOR)) {
				urlBuilder.setServerName(fHost.substring(0, fHost.indexOf(PORT_SEPARATOR)));
				urlBuilder.setPort(Integer.parseInt(fHost.substring(fHost.indexOf(PORT_SEPARATOR)+1)));
			}else {
				urlBuilder.setServerName(fHost);
				urlBuilder.setPort(80);
			}
			if (request.getHeader(PROXIED_PREFIX) == null) {
				urlBuilder.setContextPath(request.getContextPath());
			} else {
				urlBuilder.setContextPath(request.getHeader(PROXIED_PREFIX));
			}
			String loginForm = determineUrlToUseForThisRequest(request, response, authException);
			
			urlBuilder.setPathInfo(loginForm);
			return urlBuilder.getUrl();
		}
		return super.buildRedirectUrlToLoginPage(request, response, authException);
	}
}