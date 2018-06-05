package com.auth0.example;

import java.io.IOException;
import java.time.Instant;

import javax.inject.Inject;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.auth0.SessionUtils;
import com.auth0.client.auth.AuthAPI;
import com.auth0.json.auth.UserInfo;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import com.auth0.net.Request;

/**
 * Filter class to check if a valid session exists. This will be true if the User Id is present.
 */
@WebFilter(urlPatterns = "/portal/*")
public class Auth0Filter implements Filter {
	private JWTVerifier verifier;
    private String domain;
    private String clientId;
    private String clientSecret;

    @Inject
    private com.auth0.example.UserInfo info;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    	final Verification verification = JWT.require(Algorithm.none());
    	// One minute tolerance window for verification
    	verifier = verification.acceptExpiresAt(60).build();
        domain = filterConfig.getServletContext().getInitParameter("com.auth0.domain");
        clientId = filterConfig.getServletContext().getInitParameter("com.auth0.clientId");
        clientSecret = filterConfig.getServletContext().getInitParameter("com.auth0.clientSecret");
    }

    /**
     * Perform filter check on this request - verify the User Id is present.
     *
     * @param request  the received request
     * @param response the response to send
     * @param next     the next filter chain
     **/
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain next) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        String accessToken = (String) SessionUtils.get(req, "accessToken");
        String idToken = (String) SessionUtils.get(req, "idToken");
        System.out.println("Access token " + accessToken);
        System.out.println("Id token " + idToken);
        if (idToken != null) {
        	final DecodedJWT jwt = JWT.decode(idToken);
        	// Need to properly configure certificates to use verifier
        	// verifier.verify(idToken);
        	if (Instant.now().isAfter(jwt.getExpiresAt().toInstant())) {
                res.sendRedirect("/login");
                return;
        	}
        }
        if (accessToken != null && this.info.getEmail() == null) {
        	final AuthAPI auth0 = new AuthAPI(domain, clientId, clientSecret);
        	final Request<UserInfo> info = auth0.userInfo(accessToken);
        	final String nickname = (String)info.execute().getValues().get("nickname");
        	final String sub = (String)info.execute().getValues().get("sub");
        	final String name = (String)info.execute().getValues().get("name");
        	this.info.setEmail(sub.startsWith("google-oauth2") ? nickname + "@gmail.com" : name);
        }
        if (accessToken == null && idToken == null) {
            res.sendRedirect("/login");
            return;
        }
        next.doFilter(request, response);
    }

    @Override
    public void destroy() {
    }
}