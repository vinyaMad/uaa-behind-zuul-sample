# UAA (`AuthorizationServer`) load balanced behind API-GATEWAY (Edge service `Zuul`) with remote authentication

## Disclamer

**This is a fork from [kakawait's excelent POC](https://github.com/kakawait/uaa-behind-zuul-sample)**, Most of the code is exactly the same as in his POC but for the uaa-service that I have changed to remote the authentication to google (have also a facebook configuration). 

## Change Log

see [CHANGELOG.md](CHANGELOG.md)

## Overview

See [kakawait's  POC](https://github.com/kakawait/uaa-behind-zuul-sample) for basic instructions.

## Usage

I have bit tested this using kakawait's docker way, if somebody else wants to do so, feel free to report your findings. 

Before starting, you will need to setup a [Google Oauth2 app](https://developers.google.com/identity/protocols/OAuth2) using [Google API Console](https://console.developers.google.com/)

Once this is setup, on each service folder run following command:

```sh
mvn spring-boot:run
```

## Keys points of the sample

### 'Spring security' not honoring proxy x-forwarded-* headers

Kakawait's POC used plain user/password user management using a basic spring OAuth2 server. I have replaced that with a modified version of the authorization server as presented in Spring's [Spring boot and OAuth2 guide](https://spring.io/guides/tutorials/spring-boot-oauth2/). Replacing such a piece piecemeal worked, but it exposed local OAuth2 endpoints instead of using the Zuul proxied endpoints. While this works localy, it has a couple of problems:
1. it broke Kakawait's goal #3: Do not expose AuthorizationServer
2. while it works locally, it will not work if you deploy in Kubernettes or any other architecture that hides internal microservices endpoints.

To fix this I have extended Spring's LoginUrlAuthenticationEntryPoint and RequestCache

### 'ProxyAwareLogingAuthenticationEntryPoint' to honor proxy headers

LoginUrlAuthenticationEntryPoint is one of the AuthenticationEntryPoint provided by the spring security project to forward user to a login form. This class provides a buildRedirectUrlToLoginPage method that allows subclasses to change the way the URL to the login page is generated. I have extended that method in the ProxyAwareLogingAuthenticationEntryPoint so that it detects if there is a 'x-forwarded-host' proxy header and, if it is present, it generates a URL that honors those headers ('x-Forwarded-Proto', 'x-forwarded-host' and 'x-forwarded-prefix').

### extend 'HttpSessionRequestCache' to honor proxy headers

Spring Security also uses the 'HttpSessionRequestCache' mechanism to redirect the user to the original petition once it has completed the authentication process. This classes also do not honor proxy headers, so the redirection was done to the internal URL of the authentication service instead of the proxied URL exposed by Zuul. To honor those headers I have:
1. Created a 'ProxyAwareSavedRequest' that extends Spring's 'DefaultSavedRequest'  to check if there are proxy headers on the original request and honors them. The original implementation already had all the header information, but UrlUtils.buildFullRequestUrl() does not check for proxy headers. 
2. Created a 'ProxyAwareRequestCache that extends Spring Security's 'HttpSessionRequestCache' to use 'ProxyAwareSavedRequest' instead of the original 'DefaultSavedRequest'
 