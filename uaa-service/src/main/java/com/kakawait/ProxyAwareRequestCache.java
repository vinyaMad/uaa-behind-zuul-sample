package com.kakawait;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

public class ProxyAwareRequestCache extends HttpSessionRequestCache {
	//copy from HttpSessionRequestCache
	static final String SAVED_REQUEST = "SPRING_SECURITY_SAVED_REQUEST";
	@Override
	public void saveRequest(HttpServletRequest request, HttpServletResponse response) {
		// TODO Auto-generated method stub
		super.saveRequest(request, response);
		DefaultSavedRequest orig = (DefaultSavedRequest) request.getSession().getAttribute(SAVED_REQUEST);
		if (orig != null) {
			request.getSession().setAttribute(SAVED_REQUEST, new ProxyAwareSavedRequest (orig, request, new PortResolverImpl()));
		}
	}
	
}
