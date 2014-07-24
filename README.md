Apache HTTPD: mod_allowfileowner - Restrict owner of static content files
======================================================================

  * Copyright (c) 2013 SATOH Fumiyasu @ OSS Technology Corp., Japan
  * License: Apache License, Version 2.0
  * URL: <https://github.com/fumiyas/apache-mod-allowfileowner>
  * Blog: <http://fumiyas.github.io/>
  * Twitter: <https://twitter.com/satoh_fumiyasu>

What's this?
----------------------------------------------------------------------

How to use
----------------------------------------------------------------------

For Japanese:

  * http://fumiyas.github.io/apache/mod-allowfileowner.html


Build and install:

``` console
# apxs -c -i mod_allowfileowner.c
```

Example Apache `httpd.conf`:

```
LoadModule allowfileowner_module modules/mod_allowfileowner.so

<VirtualHost *>
  ## ...

  ## Set to default output filter
  SetOutputFilter ALLOWFILEOWNER

  ## Add to existing output filter
  AddOutputFilter ALLOWFILEOWNER;INCLUDES .shtml

  DocumentRoot /var/www
  <Directory /var/www>
    ## Static content files must be owned by the following users and group
    AllowFileOwner webadmin apache
    AllowFileOwnerGroup webusers
    ## ...
  </Directory>

  UserDir public_html
  <Directory /home/*/public_html>
    ## Static content files must be owned by the individual user
    AllowFileOwnerInUserDir On
  </Directory>

  ## ...
</VirtualHost>
```

Similar module
----------------------------------------------------------------------

  * https://github.com/matsumoto-r/mod_fileownercheck

