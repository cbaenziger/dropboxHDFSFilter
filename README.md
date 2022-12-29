# Committed Upstream
Note, the work here has been superceeded by the upstream work accepted in [HDFS-14234](https://issues.apache.org/jira/browse/HDFS-14234). The code here does not secure the actual datanodes, so one may work around the Namenode-only filter by requesting a specific block from a datanode using an otherwise-requested token. Such a loop-hole has been fixed in the upstream committed work.

# What is this?

This Jetty filter allows one to run WebHDFS as a "drop-box". Being a drop-box, one can write data in following standard HDFS permissioning. However, one is prohibited from reading data out (even if allowed by HDFS permissions). Regardless of ability to read data out, one may GET the properties of a file to verify that the file was written successfully or permissioned as desired. But reading the actual data via a WebHDFS `OPEN` operation will be rejected, unless specifically allowed.

Effectively, this Jetty filter will return an HTTP 403 if you are trying to read data out of WebHDFS while it will allow writes in.

# How to deploy?

This is a Jetty filter but we are not an authentication filter, so one need not set `dfs.web.authentication.filter`. The current thought is to use the namenode and datanodes's `web.xml` (e.g. `/usr/hdp/current/hadoop-hdfs-namenode/webapps/hdfs/WEB-INF/web.xml`) setting the following:
```
  <filter>
    <filter-name>DropboxAuthenticationFilter</filter-name>
    <filter-class>com.bloomberg.bach.DropboxAuthenticationFilter</filter-class>
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

# What should one see if rejected?

Attempting any GET action from the HDFS namenode using webhdfs other than GETFILECHECKSUM will result in the following error (e.g. for the `clay` user):
```
<head><title>Error 403 WebHDFS is configured write-only for clay</title></head>
<body><h2>HTTP ERROR 403</h2>
<p>Problem accessing /webhdfs/v1/user/clay/file. Reason:
<pre>    WebHDFS is configured write-only for clay@128.138.192.1</pre></p>
<hr/><i><small>Powered by Jetty://</small></i><br/>
```
