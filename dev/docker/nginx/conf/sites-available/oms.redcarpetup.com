upstream prod_oms2{
  server 127.0.0.1:4001;
}

server {
listen 80;
server_name oms2.redcarpetup.com;

	return 301 https://$host$request_uri;
}


server {
listen 443 ;
server_name oms2.redcarpetup.com;

  #proxy_cache global;
  #  proxy_cache_valid  any 1h;
  #  proxy_cache_use_stale updating;


  #ssl_certificate /etc/nginx/ssl/redcarpetup_redc_www.pem;
  #ssl_certificate_key /etc/nginx/ssl/namecheap-862404.redcarpetup.com.nopass;

 ssl on;
  ssl_certificate /etc/nginx/ssl/namecheap-1549141.unified.crt;
  ssl_certificate_key /etc/nginx/ssl/namecheap-1549141.key;
   
   # enable session resumption to improve https performance
   # http://vincent.bernat.im/en/blog/2011-ssl-session-reuse-rfc5077.html
   ssl_session_cache shared:SSL:50m;
   ssl_session_timeout 10m;
    
    # Diffie-Hellman parameter for DHE ciphersuites, recommended 2048 bits
    #ssl_dhparam /etc/nginx/ssl/dhparam.pem;
    #ssl_session_timeout 5m;
     
     # enables server-side protection from BEAST attacks
     # http://blog.ivanristic.com/2013/09/is-beast-still-a-threat.html
     ssl_prefer_server_ciphers on;
     # disable SSLv3(enabled by default since nginx 0.8.19) since it's less secure then TLS http://en.wikipedia.org/wiki/Secure_Sockets_Layer#SSL_3.0
     ssl_protocols  TLSv1 TLSv1.1 TLSv1.2;
     # ciphers chosen for forward secrecy and compatibility
     # http://blog.ivanristic.com/2013/08/configuring-apache-nginx-and-openssl-for-forward-secrecy.html
     #ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:ECDHE-RSA-RC4-SHA:ECDHE-ECDSA-RC4-SHA:RC4-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!3DES:!MD5:!PSK';
     #ssl_ciphers EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:EECDH+RC4:RSA+RC4:!MD5;
     #ssl_ciphers "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4";
     
     #duraconf
     #ssl_ciphers ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA;
     #cloudflare
     ssl_ciphers                 EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5;
      
     # enable ocsp stapling (mechanism by which a site can convey certificate revocation information to visitors in a privacy-preserving, scalable manner)
     # http://blog.mozilla.org/security/2013/07/29/ocsp-stapling-in-firefox/
     #resolver 8.8.8.8;
     #ssl_stapling on;
     #ssl_trusted_certificate /etc/nginx/ssl/star_forgott_com.crt;
      
      # config to enable HSTS(HTTP Strict Transport Security) https://developer.mozilla.org/en-US/docs/Security/HTTP_Strict_Transport_Security
      # to avoid ssl stripping https://en.wikipedia.org/wiki/SSL_stripping#SSL_stripping
      add_header Strict-Transport-Security "max-age=31536000; includeSubdomains;";

      # Prevent mobile network providers from modifying your site
      add_header "Cache-Control" "no-transform";
      # Force the latest IE version
      # Use ChromeFrame if it's installed for a better experience for the poor IE folk
      add_header "X-UA-Compatible" "IE=Edge";

        
      #... the rest of your configuration
      # config to don't allow the browser to render the page inside an frame or iframe
      # and avoid clickjacking http://en.wikipedia.org/wiki/Clickjacking
      # if you need to allow [i]frames, you can use SAMEORIGIN or even set an uri with ALLOW-FROM uri
      # https://developer.mozilla.org/en-US/docs/HTTP/X-Frame-Options
      add_header X-Frame-Options SAMEORIGIN;

      # when serving user-supplied content, include a X-Content-Type-Options: nosniff header along with the Content-Type: header,
      # to disable content-type sniffing on some browsers.
      # https://www.owasp.org/index.php/List_of_useful_HTTP_headers
      # currently suppoorted in IE > 8 http://blogs.msdn.com/b/ie/archive/2008/09/02/ie8-security-part-vi-beta-2-update.aspx
      # http://msdn.microsoft.com/en-us/library/ie/gg622941(v=vs.85).aspx
      # 'soon' on Firefox https://bugzilla.mozilla.org/show_bug.cgi?id=471020
      add_header X-Content-Type-Options nosniff;

       #This header enables the Cross-site scripting (XSS) filter built into most recent web browsers.
       # It's usually enabled by default anyway, so the role of this header is to re-enable the filter for
       # this particular website if it was disabled by the user.
       # https://www.owasp.org/index.php/List_of_useful_HTTP_headers
       add_header X-XSS-Protection "1; mode=block";

       #For Ionic js app
       add_header 'Access-Control-Allow-Origin' '*';
       add_header 'Access-Control-Allow-Credentials' 'true';
       add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS, PUT, DELETE';
       #add_header 'Access-Control-Allow-Headers' 'X-Requested-With,Accept,Content-Type,Origin,id0,id1,id2';
       add_header 'Access-Control-Allow-Headers' 'X-Requested-With,Accept,Content-Type,Origin,id0,id1,id2, RC-Timestamp,RC-HashV2';


#Rails file https://github.com/rails/rails/blob/master/actionpack/lib/action_dispatch/middleware/remote_ip.rb#L9

location  / {
	root /opt/deployer/prod_oms/react-js-new ;
      }


}

server {
listen 80;
server_name oms-cherry.redcarpetup.com;

	return 301 https://$host$request_uri;
}


server {
listen 443 ;
server_name oms-cherry.redcarpetup.com;

  #proxy_cache global;
  #  proxy_cache_valid  any 1h;
  #  proxy_cache_use_stale updating;


  #ssl_certificate /etc/nginx/ssl/redcarpetup_redc_www.pem;
  #ssl_certificate_key /etc/nginx/ssl/namecheap-862404.redcarpetup.com.nopass;

 ssl on;
  ssl_certificate /etc/nginx/ssl/namecheap-1549141.unified.crt;
  ssl_certificate_key /etc/nginx/ssl/namecheap-1549141.key;
   
   # enable session resumption to improve https performance
   # http://vincent.bernat.im/en/blog/2011-ssl-session-reuse-rfc5077.html
   ssl_session_cache shared:SSL:50m;
   ssl_session_timeout 10m;
    
    # Diffie-Hellman parameter for DHE ciphersuites, recommended 2048 bits
    #ssl_dhparam /etc/nginx/ssl/dhparam.pem;
    #ssl_session_timeout 5m;
     
     # enables server-side protection from BEAST attacks
     # http://blog.ivanristic.com/2013/09/is-beast-still-a-threat.html
     ssl_prefer_server_ciphers on;
     # disable SSLv3(enabled by default since nginx 0.8.19) since it's less secure then TLS http://en.wikipedia.org/wiki/Secure_Sockets_Layer#SSL_3.0
     ssl_protocols  TLSv1 TLSv1.1 TLSv1.2;
     # ciphers chosen for forward secrecy and compatibility
     # http://blog.ivanristic.com/2013/08/configuring-apache-nginx-and-openssl-for-forward-secrecy.html
     #ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:ECDHE-RSA-RC4-SHA:ECDHE-ECDSA-RC4-SHA:RC4-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!3DES:!MD5:!PSK';
     #ssl_ciphers EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:EECDH+RC4:RSA+RC4:!MD5;
     #ssl_ciphers "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4";
     
     #duraconf
     #ssl_ciphers ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA;
     #cloudflare
     ssl_ciphers                 EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5;
      
     # enable ocsp stapling (mechanism by which a site can convey certificate revocation information to visitors in a privacy-preserving, scalable manner)
     # http://blog.mozilla.org/security/2013/07/29/ocsp-stapling-in-firefox/
     #resolver 8.8.8.8;
     #ssl_stapling on;
     #ssl_trusted_certificate /etc/nginx/ssl/star_forgott_com.crt;
      
      # config to enable HSTS(HTTP Strict Transport Security) https://developer.mozilla.org/en-US/docs/Security/HTTP_Strict_Transport_Security
      # to avoid ssl stripping https://en.wikipedia.org/wiki/SSL_stripping#SSL_stripping
      add_header Strict-Transport-Security "max-age=31536000; includeSubdomains;";

      # Prevent mobile network providers from modifying your site
      add_header "Cache-Control" "no-transform";
      # Force the latest IE version
      # Use ChromeFrame if it's installed for a better experience for the poor IE folk
      add_header "X-UA-Compatible" "IE=Edge";

        
      #... the rest of your configuration
      # config to don't allow the browser to render the page inside an frame or iframe
      # and avoid clickjacking http://en.wikipedia.org/wiki/Clickjacking
      # if you need to allow [i]frames, you can use SAMEORIGIN or even set an uri with ALLOW-FROM uri
      # https://developer.mozilla.org/en-US/docs/HTTP/X-Frame-Options
      add_header X-Frame-Options SAMEORIGIN;

      # when serving user-supplied content, include a X-Content-Type-Options: nosniff header along with the Content-Type: header,
      # to disable content-type sniffing on some browsers.
      # https://www.owasp.org/index.php/List_of_useful_HTTP_headers
      # currently suppoorted in IE > 8 http://blogs.msdn.com/b/ie/archive/2008/09/02/ie8-security-part-vi-beta-2-update.aspx
      # http://msdn.microsoft.com/en-us/library/ie/gg622941(v=vs.85).aspx
      # 'soon' on Firefox https://bugzilla.mozilla.org/show_bug.cgi?id=471020
      add_header X-Content-Type-Options nosniff;

       #This header enables the Cross-site scripting (XSS) filter built into most recent web browsers.
       # It's usually enabled by default anyway, so the role of this header is to re-enable the filter for
       # this particular website if it was disabled by the user.
       # https://www.owasp.org/index.php/List_of_useful_HTTP_headers
       add_header X-XSS-Protection "1; mode=block";

       #For Ionic js app
       add_header 'Access-Control-Allow-Origin' '*';
       add_header 'Access-Control-Allow-Credentials' 'true';
       add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS, PUT, DELETE';
       #add_header 'Access-Control-Allow-Headers' 'X-Requested-With,Accept,Content-Type,Origin,id0,id1,id2';
       add_header 'Access-Control-Allow-Headers' 'X-Requested-With,Accept,Content-Type,Origin,id0,id1,id2, RC-Timestamp,RC-HashV2';


#Rails file https://github.com/rails/rails/blob/master/actionpack/lib/action_dispatch/middleware/remote_ip.rb#L9

location  / {
	root /opt/deployer/cherry_oms/react-js-new ;
      }


}



server {
listen 80;
server_name oms.redcarpetup.com;

	return 301 https://$host$request_uri;
}


server {
listen 443 ;
server_name oms.redcarpetup.com;

  #proxy_cache global;
  #  proxy_cache_valid  any 1h;
  #  proxy_cache_use_stale updating;


  #ssl_certificate /etc/nginx/ssl/redcarpetup_redc_www.pem;
  #ssl_certificate_key /etc/nginx/ssl/namecheap-862404.redcarpetup.com.nopass;

 ssl on;
  ssl_certificate /etc/nginx/ssl/namecheap-1549141.unified.crt;
  ssl_certificate_key /etc/nginx/ssl/namecheap-1549141.key;
   
   # enable session resumption to improve https performance
   # http://vincent.bernat.im/en/blog/2011-ssl-session-reuse-rfc5077.html
   ssl_session_cache shared:SSL:50m;
   ssl_session_timeout 10m;
    
    # Diffie-Hellman parameter for DHE ciphersuites, recommended 2048 bits
    #ssl_dhparam /etc/nginx/ssl/dhparam.pem;
    #ssl_session_timeout 5m;
     
     # enables server-side protection from BEAST attacks
     # http://blog.ivanristic.com/2013/09/is-beast-still-a-threat.html
     ssl_prefer_server_ciphers on;
     # disable SSLv3(enabled by default since nginx 0.8.19) since it's less secure then TLS http://en.wikipedia.org/wiki/Secure_Sockets_Layer#SSL_3.0
     ssl_protocols  TLSv1 TLSv1.1 TLSv1.2;
     # ciphers chosen for forward secrecy and compatibility
     # http://blog.ivanristic.com/2013/08/configuring-apache-nginx-and-openssl-for-forward-secrecy.html
     #ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:ECDHE-RSA-RC4-SHA:ECDHE-ECDSA-RC4-SHA:RC4-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!3DES:!MD5:!PSK';
     #ssl_ciphers EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:EECDH+RC4:RSA+RC4:!MD5;
     #ssl_ciphers "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4";
     
     #duraconf
     #ssl_ciphers ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA;
     #cloudflare
     ssl_ciphers                 EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5;
      
     # enable ocsp stapling (mechanism by which a site can convey certificate revocation information to visitors in a privacy-preserving, scalable manner)
     # http://blog.mozilla.org/security/2013/07/29/ocsp-stapling-in-firefox/
     #resolver 8.8.8.8;
     #ssl_stapling on;
     #ssl_trusted_certificate /etc/nginx/ssl/star_forgott_com.crt;
      
      # config to enable HSTS(HTTP Strict Transport Security) https://developer.mozilla.org/en-US/docs/Security/HTTP_Strict_Transport_Security
      # to avoid ssl stripping https://en.wikipedia.org/wiki/SSL_stripping#SSL_stripping
      add_header Strict-Transport-Security "max-age=31536000; includeSubdomains;";

      # Prevent mobile network providers from modifying your site
      add_header "Cache-Control" "no-transform";
      # Force the latest IE version
      # Use ChromeFrame if it's installed for a better experience for the poor IE folk
      add_header "X-UA-Compatible" "IE=Edge";

        
      #... the rest of your configuration
      # config to don't allow the browser to render the page inside an frame or iframe
      # and avoid clickjacking http://en.wikipedia.org/wiki/Clickjacking
      # if you need to allow [i]frames, you can use SAMEORIGIN or even set an uri with ALLOW-FROM uri
      # https://developer.mozilla.org/en-US/docs/HTTP/X-Frame-Options
      add_header X-Frame-Options SAMEORIGIN;

      # when serving user-supplied content, include a X-Content-Type-Options: nosniff header along with the Content-Type: header,
      # to disable content-type sniffing on some browsers.
      # https://www.owasp.org/index.php/List_of_useful_HTTP_headers
      # currently suppoorted in IE > 8 http://blogs.msdn.com/b/ie/archive/2008/09/02/ie8-security-part-vi-beta-2-update.aspx
      # http://msdn.microsoft.com/en-us/library/ie/gg622941(v=vs.85).aspx
      # 'soon' on Firefox https://bugzilla.mozilla.org/show_bug.cgi?id=471020
      add_header X-Content-Type-Options nosniff;

       #This header enables the Cross-site scripting (XSS) filter built into most recent web browsers.
       # It's usually enabled by default anyway, so the role of this header is to re-enable the filter for
       # this particular website if it was disabled by the user.
       # https://www.owasp.org/index.php/List_of_useful_HTTP_headers
       add_header X-XSS-Protection "1; mode=block";

       #For Ionic js app
       add_header 'Access-Control-Allow-Origin' '*';
       add_header 'Access-Control-Allow-Credentials' 'true';
       add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS, PUT, DELETE';
       #add_header 'Access-Control-Allow-Headers' 'X-Requested-With,Accept,Content-Type,Origin,id0,id1,id2';
       add_header 'Access-Control-Allow-Headers' 'X-Requested-With,Accept,Content-Type,Origin,id0,id1,id2, RC-Timestamp,RC-HashV2';


#Rails file https://github.com/rails/rails/blob/master/actionpack/lib/action_dispatch/middleware/remote_ip.rb#L9

  
	root /opt/deployer/prod_oms/dist ;
        index index.html index.htm;
   	location  / {
	 try_files $uri /index.html;
	}
         # CSS and Javascript
        location ~* \.(?:css|js)$ {
         expires 1y;
         access_log off;
         add_header Cache-Control "public";
         add_header SSS-Control "sss-public";
         add_header ETag "";
        }
        # Prevent clients from accessing hidden files (starting with a dot)
      # This is particularly important if you store .htpasswd files in the site hierarchy
      location ~* (?:^|/)\. {
          deny all;
      }
      # Prevent clients from accessing to backup/config/source files
      location ~* (?:\.(?:bak|config|sql|fla|psd|ini|log|sh|inc|swp|dist)|~)$ {
          deny all;
      }

      #location / {
      #  proxy_set_header Host $host;
      #	proxy_set_header X-Forwarded-Proto $scheme;
      #  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      #  proxy_pass http://prod_oms2; # match the name of upstream directive which is defined above
      #}


}
