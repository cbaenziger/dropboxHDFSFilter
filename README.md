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
      <param-value>ubuntu,192.168.0.1/24,/webhdfs/v1/user/ubuntu/file|specialuser,8.0.0.0/8,/webhdfs/v1/user/special/my_file</param-value>
    </init-param>
  </filter>
  <filter-mapping>
    <filter-name>DropboxAuthenticationFilter</filter-name>
    <url-pattern>/webhdfs/*</url-pattern>
  </filter-mapping>
```

# What should one see?

Attempting any GET action from the HDFS namenode using webhdfs other than GETFILECHECKSUM will result in the following error (e.g. for the `clay` user):
```
<head><title>Error 403 WebHDFS is configured write-only for clay</title></head>
<body><h2>HTTP ERROR 403</h2>
<p>Problem accessing /webhdfs/v1/user/clay/file. Reason:
<pre>    WebHDFS is configured write-only for clay</pre></p>
<hr/><i><small>Powered by Jetty://</small></i><br/>
```
