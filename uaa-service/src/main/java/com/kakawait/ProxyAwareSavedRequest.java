package com.kakawait;

import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.web.PortResolver;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.util.UrlUtils;

public class ProxyAwareSavedRequest extends DefaultSavedRequest{
	private DefaultSavedRequest orig;
	public ProxyAwareSavedRequest (DefaultSavedRequest orig, HttpServletRequest request, PortResolver portResolver) {
		super(request, portResolver);
		this.orig = orig;
	}
	@Override
	public boolean doesRequestMatch(HttpServletRequest request, PortResolver portResolver) {
		return this.orig.doesRequestMatch(request, portResolver);
	}
	@Override
	public String getContextPath() {
		return this.orig.getContextPath();
	}
	@Override
	public List<Cookie> getCookies() {
		return this.orig.getCookies();
	}
	@Override
	public String getRedirectUrl() {
		if (this.orig.getHeaderValues(ProxyAwareLogingAuthenticationEntryPoint.PROXIED_HOST)!= null) {
			String fHost = this.orig.getHeaderValues(ProxyAwareLogingAuthenticationEntryPoint.PROXIED_HOST).get(0);
			String serverName;
			int port;
			if (fHost.contains(ProxyAwareLogingAuthenticationEntryPoint.PORT_SEPARATOR)) {
				serverName = fHost.substring(0, fHost.indexOf(ProxyAwareLogingAuthenticationEntryPoint.PORT_SEPARATOR));
				port = Integer.parseInt(fHost.substring(fHost.indexOf(ProxyAwareLogingAuthenticationEntryPoint.PORT_SEPARATOR)+1));
			}else {
				serverName = fHost;
				port = 80;
			}
			 return UrlUtils.buildFullRequestUrl(
					 this.orig.getHeaderValues(ProxyAwareLogingAuthenticationEntryPoint.PROXIED_PROTO).size() == 0?this.orig.getScheme():
						 this.orig.getHeaderValues(ProxyAwareLogingAuthenticationEntryPoint.PROXIED_PROTO).get(0), 
					 serverName, 
					 port, 
					 this.orig.getRequestURI(),
					 this.orig.getQueryString());
		} 
		return this.orig.getRedirectUrl();
	}
	@Override
	public Collection<String> getHeaderNames() {
		return this.orig.getHeaderNames();
	}
	@Override
	public List<String> getHeaderValues(String name) {
		return this.orig.getHeaderValues(name);
	}
	@Override
	public List<Locale> getLocales() {
		return this.orig.getLocales();
	}
	@Override
	public String getMethod() {
		return this.orig.getMethod();
	}
	@Override
	public Map<String, String[]> getParameterMap() {
		return this.orig.getParameterMap();
	}
	@Override
	public Collection<String> getParameterNames() {
		return this.orig.getParameterNames();
	}
	@Override
	public String[] getParameterValues(String name) {
		return this.orig.getParameterValues(name);
	}
	@Override
	public String getPathInfo() {
		return this.orig.getPathInfo();
	}
	@Override
	public String getQueryString() {
		return this.orig.getQueryString();
	}
	@Override
	public String getRequestURI() {
		return this.orig.getRequestURI();
	}
	@Override
	public String getRequestURL() {
		return this.orig.getRequestURL();
	}
	@Override
	public String getScheme() {
		return this.orig.getScheme();
	}
	@Override
	public String getServerName() {
		return this.orig.getServerName();
	}
	@Override
	public int getServerPort() {
		return this.orig.getServerPort();
	}
	@Override
	public String getServletPath() {
		return this.orig.getServletPath();
	}
	@Override
	public String toString() {
		return this.orig.toString();
	}

}
