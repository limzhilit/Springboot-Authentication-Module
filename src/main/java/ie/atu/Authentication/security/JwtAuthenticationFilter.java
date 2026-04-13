package ie.atu.Authentication.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

  private final JwtUtil jwtUtil;

  public JwtAuthenticationFilter(JwtUtil jwtUtil) {
    this.jwtUtil = jwtUtil;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request,
                                  HttpServletResponse response,
                                  FilterChain filterChain) throws ServletException, IOException {

    String path = request.getRequestURI();
    System.out.println("Path: " + path);

    String servletPath = request.getServletPath();
    if (servletPath != null && servletPath.startsWith("/h2-console")
        || servletPath.startsWith("/swagger-ui")) {
      filterChain.doFilter(request, response);
      return;
    }
    if (path.startsWith("/api/auth")) {
      filterChain.doFilter(request, response);
      return;
    }
    if (path.startsWith("/api/auth/refresh-token")) {
      System.out.println("Refresh token path");
      filterChain.doFilter(request, response); // skip auth check for refresh
      return;
    }

    String authHeader = request.getHeader("Authorization");

    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      System.out.println("No token in header");
      filterChain.doFilter(request, response);
      return;
    }

    String token = authHeader.substring(7);
    String id = jwtUtil.validateToken(token).getSubject();

    if (id != null && SecurityContextHolder.getContext().getAuthentication() == null) {
      UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
          id, null, List.of()
      );
      authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
      SecurityContextHolder.getContext().setAuthentication(authToken);
    }

    filterChain.doFilter(request, response);
  }
}