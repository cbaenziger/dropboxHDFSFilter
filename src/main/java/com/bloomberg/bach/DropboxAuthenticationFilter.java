package com.bloomberg.bach;

import javax.servlet.ServletException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.hadoop.hdfs.web.AuthFilter;
import org.apache.hadoop.security.authentication.server.AuthenticationFilter;
import java.util.ArrayList;
import java.util.Enumeration;
import java.lang.Iterable;
import java.util.Iterator;
import java.util.Map;
import java.util.Collections;
import java.util.HashMap;
import java.util.Optional;
import org.apache.commons.net.util.SubnetUtils;
import org.apache.commons.io.FilenameUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DropboxAuthenticationFilter implements Filter {
  private Logger LOG = LoggerFactory.getLogger(DropboxAuthenticationFilter.class);
  public static final String WEBHDFS_ROOT = "/webhdfs/v1";
  public static final String HDFS_CONFIG_PREFIX = "dfs.web.authentication.";
  public static final String DROPBOX_CONFIG = "dropbox.allow.rule";
  private HashMap<String, ArrayList<Rule>> RULEMAP = null;

  private class Rule {
    private final SubnetUtils.SubnetInfo subnet;
    private final String path;

    /*
     * A class for holding dropbox filter rules
     *
     * @param subnet - the IPv4 subnet for which this rule is valid (pass null for
     * any network location)
     *
     * @param path - the HDFS path for which this rule is valid
     */
    Rule(SubnetUtils.SubnetInfo subnet, String path) {
      this.subnet = subnet;
      this.path = path;
    }

    public SubnetUtils.SubnetInfo getSubnet() {
      return(subnet);
    }

    public String getPath() {
      return(path);
    }
  }

  /*
   * Check all rules for this user to see if one matches for this host/path pair
   *
   * @Param: user - user to check rules for
   *
   * @Param: host - IP address (e.g. "192.168.0.1")
   *
   * @Param: path - file path with no scheme (e.g. /path/foo)
   *
   * @Returns: true if a rule matches this user, host, path tuple false if an
   * error occurs or no match
   */
  private boolean matchRule(String user, String remoteIp, String path) {
    // allow lookups for blank in the rules for user and path
    user = (user == null ? "" : user);
    path = (path == null ? "" : path);

    ArrayList<Rule> userRules = RULEMAP.get(user);
    ArrayList<Rule> anyRules = RULEMAP.get("*");
    if(anyRules != null) {
      if(userRules != null) {
        userRules.addAll(RULEMAP.get("*"));
      } else {
        userRules = anyRules;
      }
    }

    LOG.trace("Got user: {}, remoteIp: {}, path: {}", user, remoteIp, path);

    // isInRange fails for null/blank IPs, require an IP to approve
    if(remoteIp == null) {
      LOG.trace("Returned false due to null rempteIp");
      return false;
    }

    if(userRules != null) {
      for(Rule rule : userRules) {
        LOG.trace("Evaluating rule, subnet: {}, path: {}",
                  rule.getSubnet() != null ? rule.getSubnet().getCidrSignature() : null, rule.getPath());
        try {
          if((rule.getSubnet() == null || rule.getSubnet().isInRange(remoteIp))
              && FilenameUtils.directoryContains(WEBHDFS_ROOT + rule.getPath(), path)) {
            LOG.debug("Found matching rule, subnet: {}, path: {}; returned true",
                      rule.getSubnet() != null ? rule.getSubnet().getCidrSignature() : null, rule.getPath());
            return true;
          }
        } catch(IOException e) {
          LOG.warn("Got IOException {}; returned false", e);
          return false;
        }
      }
    }
    LOG.trace("Found no rules for user");
    return false;
  }

  private static class WrapperFilterConfig implements FilterConfig {
    final Map<String, String> map;
    final FilterConfig parentConfig;

    WrapperFilterConfig(FilterConfig fc, Map<String, String> map) {
      this.parentConfig = fc;
      Map<String, String> m = new HashMap<String, String>(map);
      Enumeration<String> params = fc.getInitParameterNames();
      while(params.hasMoreElements()) {
        String param = (String) params.nextElement();
        m.put(param, fc.getInitParameter(param));
      }
      this.map = m;
    }

    @Override
    public String getFilterName() {
      return parentConfig.getFilterName();
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
      return parentConfig.getServletContext();
    }
  }

  @Override
  public void destroy() {
    RULEMAP = null;
  }

  @Override
  public void init(FilterConfig config) throws ServletException {
    HashMap overrideConfigs = new HashMap<String, String>();

    // Process dropbox rules
    String dropboxRules = config.getInitParameter(DROPBOX_CONFIG);
    if(dropboxRules != null) {
      // name: dropbox.allow.rule
      // value: user,network/bits,path glob|
      String[] rules = dropboxRules.split("\\||\n");
      RULEMAP = new HashMap<String, ArrayList<Rule>>(rules.length);
      for(String line : rules) {
        String[] parts = line.split(",", 3);
        LOG.debug("Loaded rule: user: " + parts[0] + " network/bits: " + parts[1] + " path: " + parts[2]);
        String globPattern = parts[2];
        // Map is {"user": [subnet, path]}
        Rule rule = null;
        if(parts[1].equals("*")) {
          rule = new Rule(null, globPattern);
        } else {
          rule = new Rule(new SubnetUtils(parts[1]).getInfo(), globPattern);
        }
        // Update the rule map with this rule
        ArrayList<Rule> ruleList = RULEMAP.getOrDefault(parts[0], new ArrayList<Rule>() {
        });
        ruleList.add(rule);
        RULEMAP.put(parts[0], ruleList);
      }
    } else {
      // make an empty hash since we have no rules
      RULEMAP = new HashMap(0);
    }

    Enumeration<String> params = config.getInitParameterNames();
    while(params.hasMoreElements()) {
      String param = (String) params.nextElement();

      if(param.startsWith(HDFS_CONFIG_PREFIX)) {
        overrideConfigs.put(param.substring(HDFS_CONFIG_PREFIX.length()), config.getInitParameter(param));
      }
    }

    if(config.getInitParameter(AuthenticationFilter.AUTH_TYPE) == null) {
      overrideConfigs.put(AuthenticationFilter.AUTH_TYPE, "kerberos");
    }

    config = new WrapperFilterConfig(config, overrideConfigs);

    params = config.getInitParameterNames();
    while(params.hasMoreElements()) {
      String param = (String) params.nextElement();
      LOG.debug("Configuration parameter: {}:{}", param, config.getInitParameter(param));
    }
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
      throws IOException, ServletException {
    final HttpServletRequest httpRequest = (HttpServletRequest) request;
    HttpServletResponse httpResponse = (HttpServletResponse) response;

    final String address = request.getRemoteAddr();
    final String user = httpRequest.getRemoteUser();
    final String uri = httpRequest.getRequestURI();
    final Optional<String> query = Optional.ofNullable(httpRequest.getQueryString());

    // need the authorization filter to run first so we know who's making the call
    filterChain.doFilter(request, response);

    if("GET".equalsIgnoreCase(httpRequest.getMethod()) && !matchRule("*", address, uri)
        && !matchRule(user, address, uri)
        && !query.map((q) -> q.trim().equalsIgnoreCase("op=GETFILECHECKSUM")).orElse(false)) {
      if(!response.isCommitted()) {
        httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN,
            "WebHDFS is configured write-only for " + user + "@" + address);
      }
    }
  }
}
