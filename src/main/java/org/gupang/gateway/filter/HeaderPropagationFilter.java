package org.gupang.gateway.filter;

import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class HeaderPropagationFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        final String keycloakId;
        final String username;
        final String role;

        // JAVA16 이후 instanceof는 형태가 일치하는지 체크해서 boolean값 주고 변수에 할당까지 해준다고 함
        if (authentication != null && authentication.getPrincipal() instanceof Jwt jwt) {
            keycloakId = jwt.getSubject();
            username = jwt.getClaimAsString("preferred_username");
            role = jwt.getClaimAsString("role");
        } else {
            keycloakId = username = role = null;
        }

        httpRequest = new HttpServletRequestWrapper(httpRequest) {
            @Override
            public String getHeader(String n) {
                if ("X-User-UserId".equalsIgnoreCase(n))
                    return keycloakId;
                if ("X-User-Username".equalsIgnoreCase(n))
                    return username;
                if ("X-User-Role".equalsIgnoreCase(n))
                    return role;
                return super.getHeader(n);
            }

            @Override
            public Enumeration<String> getHeaders(String name) {
                if ("X-User-UserId".equalsIgnoreCase(name))
                    return keycloakId != null ? Collections.enumeration(Collections.singletonList(keycloakId))
                            : Collections.emptyEnumeration();
                if ("X-User-Username".equalsIgnoreCase(name))
                    return username != null ? Collections.enumeration(Collections.singletonList(username))
                            : Collections.emptyEnumeration();
                if ("X-User-Role".equalsIgnoreCase(name))
                    return role != null ? Collections.enumeration(Collections.singletonList(role))
                            : Collections.emptyEnumeration();
                return super.getHeaders(name);
            }

            @Override
            public Enumeration<String> getHeaderNames() {
                List<String> names = Collections.list(super.getHeaderNames());

                // 위변조 방지
                names.removeIf(n -> n.equalsIgnoreCase("X-User-UserId") ||
                        n.equalsIgnoreCase("X-User-Username") ||
                        n.equalsIgnoreCase("X-User-Role"));

                if (keycloakId != null)
                    names.add("X-User-UserId");
                if (username != null)
                    names.add("X-User-Username");
                if (role != null)
                    names.add("X-User-Role");

                return Collections.enumeration(names);
            }
        };

        chain.doFilter(httpRequest, response);
    }
}
