package com.bloomberg.bach;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

import java.io.IOException;
import java.lang.StringBuffer;
import java.util.Arrays;
import java.util.Vector;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.mockito.Mockito;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.hadoop.security.authentication.server.AuthenticationFilter;
import org.apache.hadoop.hdfs.web.WebHdfsFileSystem;

public class TestDropboxAuthenticationFilter {
  private Logger log = LoggerFactory.getLogger(TestDropboxAuthenticationFilter.class);

  /*
   * Test running in unrestricted mode
   */
  @Test
  public void testAcceptAll() throws Exception {
    HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    Mockito.when(request.getRemoteAddr()).thenReturn(null);
    Mockito.when(request.getMethod()).thenReturn("GET");
    Mockito.when(request.getRequestURI())
        .thenReturn(new StringBuffer(WebHdfsFileSystem.PATH_PREFIX + "/user/ubuntu/foo").toString());
    Mockito.when(request.getQueryString()).thenReturn("op=OPEN");
    Mockito.when(request.getRemoteAddr()).thenReturn("192.168.1.2");

    HttpServletResponse response = Mockito.mock(HttpServletResponse.class);

    FilterChain chain = new FilterChain() {
      @Override
      public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse)
          throws IOException, ServletException {
      }
    };

    Filter filter = new DropboxAuthenticationFilter();

    HashMap<String, String> configs = new HashMap<String, String>() {
    };
    String allowRule = "*,*,/";
    log.trace("Passing configs:\n{}", allowRule);
    configs.put("dropbox.allow.rules", allowRule);
    configs.put(AuthenticationFilter.AUTH_TYPE, "simple");
    FilterConfig fc = new DummyFilterConfig(configs);

    filter.init(fc);
    filter.doFilter(request, response, chain);
    Mockito.verify(response, Mockito.times(0)).sendError(Mockito.eq(HttpServletResponse.SC_FORBIDDEN),
        Mockito.anyString());
    filter.destroy();
  }

  /*
   * Test accepting a GET request for the file checksum when prohibited from doing
   * a GET open call
   */
  @Test
  public void testAcceptGETFILECHECKSUM() throws Exception {
    HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    Mockito.when(request.getRemoteAddr()).thenReturn(null);
    Mockito.when(request.getMethod()).thenReturn("GET");
    Mockito.when(request.getRequestURI())
        .thenReturn(new StringBuffer(WebHdfsFileSystem.PATH_PREFIX + "/user/ubuntu/").toString());
    Mockito.when(request.getQueryString()).thenReturn("op=GETFILECHECKSUM ");
    Mockito.when(request.getRemoteAddr()).thenReturn("192.168.1.2");

    HttpServletResponse response = Mockito.mock(HttpServletResponse.class);

    FilterChain chain = new FilterChain() {
      @Override
      public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse)
          throws IOException, ServletException {
      }
    };

    Filter filter = new DropboxAuthenticationFilter();

    HashMap configs = new HashMap<String, String>() {
    };
    configs.put(AuthenticationFilter.AUTH_TYPE, "simple");
    FilterConfig fc = new DummyFilterConfig(configs);

    filter.init(fc);
    filter.doFilter(request, response, chain);
    Mockito.verify(response, Mockito.times(0)).sendError(Mockito.eq(HttpServletResponse.SC_FORBIDDEN),
        Mockito.anyString());
    filter.destroy();
  }

  /*
   * Test accepting a GET request for reading a file via an open call
   */
  @Test
  public void testRuleAllowedGet() throws Exception {
    HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    Mockito.when(request.getRemoteAddr()).thenReturn(null);
    Mockito.when(request.getMethod()).thenReturn("GET");
    Mockito.when(request.getRequestURI())
        .thenReturn(new StringBuffer(WebHdfsFileSystem.PATH_PREFIX + "/user/ubuntu/foo").toString());
    Mockito.when(request.getQueryString()).thenReturn("op=OPEN");
    Mockito.when(request.getRemoteAddr()).thenReturn("192.168.1.2");

    HttpServletResponse response = Mockito.mock(HttpServletResponse.class);

    FilterChain chain = new FilterChain() {
      @Override
      public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse)
          throws IOException, ServletException {
      }
    };

    Filter filter = new DropboxAuthenticationFilter();

    HashMap configs = new HashMap<String, String>() {
    };
    String allowRule = "ubuntu,127.0.0.1/32,/localbits/*|ubuntu,192.168.0.1/22,/user/ubuntu/*";
    log.trace("Passing configs:\n{}", allowRule);
    configs.put("dropbox.allow.rules", allowRule);
    configs.put(AuthenticationFilter.AUTH_TYPE, "simple");
    FilterConfig fc = new DummyFilterConfig(configs);

    filter.init(fc);
    filter.doFilter(request, response, chain);
    filter.destroy();
  }

  /*
   * Test by default we deny an open call GET request
   */
  @Test
  public void testRejectsGETs() throws Exception {
    HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    Mockito.when(request.getRemoteAddr()).thenReturn(null);
    Mockito.when(request.getMethod()).thenReturn("GET");
    Mockito.when(request.getRequestURI())
        .thenReturn(new StringBuffer(WebHdfsFileSystem.PATH_PREFIX + "/user/ubuntu/").toString());
    Mockito.when(request.getQueryString()).thenReturn("delegationToken=foo&op=OPEN ");
    Mockito.when(request.getRemoteAddr()).thenReturn("192.168.1.2");

    HttpServletResponse response = Mockito.mock(HttpServletResponse.class);

    FilterChain chain = new FilterChain() {
      @Override
      public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse)
          throws IOException, ServletException {
      }
    };

    Filter filter = new DropboxAuthenticationFilter();

    HashMap configs = new HashMap<String, String>() {
    };
    configs.put(AuthenticationFilter.AUTH_TYPE, "simple");
    FilterConfig fc = new DummyFilterConfig(configs);

    filter.init(fc);
    filter.doFilter(request, response, chain);
    Mockito.verify(response).sendError(Mockito.eq(HttpServletResponse.SC_FORBIDDEN), Mockito.anyString());
    filter.destroy();
  }

  private static class DummyFilterConfig implements FilterConfig {
    final Map<String, String> map;

    DummyFilterConfig(Map<String, String> map) {
      this.map = map;
    }

    @Override
    public String getFilterName() {
      return "dummy";
    }

    @Override
    public String getInitParameter(String arg0) {
      return map.get(arg0);
    }

    @Override
    public Enumeration<String> getInitParameterNames() {
      return Collections.enumeration(map.keySet());
    }

    @Override
    public ServletContext getServletContext() {
      ServletContext context = Mockito.mock(ServletContext.class);
      Mockito.when(context.getAttribute(AuthenticationFilter.SIGNER_SECRET_PROVIDER_ATTRIBUTE)).thenReturn(null);
      return context;
    }
  }
}
