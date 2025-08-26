package net.jforum.csrf;

import java.io.IOException;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.apache.commons.fileupload2.jakarta.servlet6.JakartaServletFileUpload;
import org.apache.commons.fileupload2.jakarta.servlet6.JakartaServletRequestContext;
import org.owasp.csrfguard.CsrfGuard;
import org.owasp.csrfguard.http.InterceptRedirectResponse;
import org.owasp.csrfguard.log.LogLevel;

import net.jforum.context.RequestContext;
import net.jforum.context.web.WebRequestContext;

/**
 * Didn't use OWASP filter because couldn't map jforum actions to urls consistently.
 * Copied from OWASP and added getJForumMethodName() and changed logic near isValidRequest line.
 * 
 * @author Jeanne Boyarsky
 */

public class CsrfFilter implements Filter {

    public static final String OWASP_CSRF_TOKEN_NAME = "OWASP_CSRFTOKEN";

    private FilterConfig filterConfig = null;

    @Override public void destroy() {
        filterConfig = null;
    }

    @Override public void init (FilterConfig filterConfig) throws ServletException {
        this.filterConfig = filterConfig;
    }

    private String getJForumMethodName (HttpServletRequest req) throws IOException {
        String module = null;
        boolean multiPart = JakartaServletFileUpload.isMultipartContent(new JakartaServletRequestContext(req));
        /*
         * If a multipart request, we know that CSRF protection is needed (it is a post/upload).
		 * Don't actually look up the module since that will cause the input stream
		 * to get read and then be unavailable for the real request.
         */
        if (multiPart) {
            module = "multipart request: " + req.getRequestURI();
        } else {
            RequestContext request = new WebRequestContext(req);
            module = request.getAction();
            if (module == null) {
                module = "unknown module for " + req.getRequestURI();
            }
        }
        
        return module;
    }

    @Override public void doFilter (ServletRequest request, ServletResponse response, FilterChain filterChain)
			throws IOException, ServletException {
        /** only work with HttpServletRequest objects **/
        if (request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
            CsrfGuard csrfGuard = CsrfGuard.getInstance();
            HttpServletRequest httpRequest = (HttpServletRequest) request;
            HttpSession session = httpRequest.getSession(false);
            if (session == null) {
                // If there is no session, no harm can be done
                filterChain.doFilter(httpRequest, (HttpServletResponse) response);
                // added this because wasn't creating tokens on initial request
				try {
					session = httpRequest.getSession(true);
				} catch (IllegalStateException isex) {
					/* throws "Cannot create a session after the response has been committed" */
				}
                csrfGuard.updateTokens(httpRequest);
                return;
            }
            csrfGuard.getLogger().log(LogLevel.Debug, String.format("CsrfGuard analyzing request %s", httpRequest.getRequestURI()));
            InterceptRedirectResponse httpResponse = new InterceptRedirectResponse((HttpServletResponse) response, httpRequest, csrfGuard);
            // if (MultipartHttpServletRequest.isMultipartRequest(httpRequest)) {
            //     httpRequest = new MultipartHttpServletRequest(httpRequest);
            // }
            /**
             * Custom code
             */
            // bypass uri ends with /
            if (httpRequest.getRequestURI().endsWith("/")) {
            	csrfGuard.getLogger().log("bypass uri="+httpRequest.getRequestURI());
            	filterChain.doFilter(httpRequest, httpResponse);
            	return;            	
            }
            String name = getJForumMethodName(httpRequest);
            CsrfHttpServletRequestWrapper csrfRequestWrapper = new CsrfHttpServletRequestWrapper(httpRequest, name);
            if (session.isNew() && csrfGuard.isUseNewTokenLandingPage()) {
                csrfGuard.writeLandingPage(httpRequest, httpResponse);                
            } else if (csrfGuard.isValidRequest(csrfRequestWrapper, httpResponse)) {
                filterChain.doFilter(httpRequest, httpResponse);
            } else {
                /** invalid request - nothing to do - actions already executed **/
            }
            /** update tokens **/
            csrfGuard.updateTokens(httpRequest);
        } else {
            filterConfig.getServletContext().log(
				String.format("[WARNING] CsrfGuard does not know how to work with requests of class %s ", request.getClass().getName()));
            filterChain.doFilter(request, response);
        }
    }
}

