# What is this?
This Jetty filter will return a 403 if you are trying to read data out of WebHDFS while it will allow writes in.

# How to deploy?

This is a Jetty filter but we are not an authentication filter, so do not need to set `dfs.web.authentication.filter`. The current thought is to use the namenode's `web.xml` (e.g. `/usr/hdp/current/hadoop-hdfs-namenode/webapps/hdfs/WEB-INF/web.xml`) setting the following:
```
  <filter>
    <filter-name>DropboxAuthenticationFilter</filter-name>
    <filter-class>com.bloomberg.dropboxFilter.DropboxAuthenticationFilter</filter-class>
    <init-param>
      <param-name>kerberos.keytab</param-name>
      <param-value>/etc/security/keytabs/spnego.service.keytab</param-value>
    </init-param>
    <init-param>
      <param-name>kerberos.principal</param-name>
      <param-value>HTTP/f-rebase-bcpc-vm1.bcpc.example.com@BCPC.EXAMPLE.COM</param-value>
    </init-param>
    <init-param>
      <param-name>dropbox.allow.rules</param-name>
      <param-value>admin,*,/
specialuser,8.0.0.0/8,/user/special/
*,*,/public|*,192.168.1.0/24,/internal_only</param-value>
    </init-param>
  </filter>
  <filter-mapping>
    <filter-name>DropboxAuthenticationFilter</filter-name>
    <url-pattern>/webhdfs/*</url-pattern>
  </filter-mapping>
```

# How does one configure the access rules?
The rules are passed in via filter parameters for the `dropbox.allow.rules` parameter to the filter class. Rules are allow rules; if no rule are configured no reads will be allowed. Rules are newline or `|` delimited. The rule format is `user,subnet,path`:
* User can be the specific username or `*` for any user.
* Subnet is a CIDR notation IP network (or `*` for any IP address); this uses the Apache Commons Net [`SubnetUtils`](https://commons.apache.org/proper/commons-net/apidocs/org/apache/commons/net/util/SubnetUtils.html) class for IP matching; at this time it is thus IPv4 limited and does not accept 0.0.0.0/0 for any address. One may use a.b.c.d/32 for a specific host.
* Path is a directory path. Any file under that directory may be read. (To disable the filter one may provide `/` as the path to match any file.)

# What should one see?

Attempting any GET action from the HDFS namenode using webhdfs other than GETFILECHECKSUM will result in the following error (e.g. for the `clay` user):
```
<head><title>Error 403 WebHDFS is configured write-only for clay</title></head>
<body><h2>HTTP ERROR 403</h2>
<p>Problem accessing /webhdfs/v1/user/clay/file. Reason:
<pre>    WebHDFS is configured write-only for clay</pre></p>
<hr/><i><small>Powered by Jetty://</small></i><br/>
```
