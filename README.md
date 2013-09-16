Apache HTTPD: mod_allowfileowner - Restrict owner of static content files
======================================================================

  * Copyright (c) 2013 SATOH Fumiyasu @ OSS Technology Corp., Japan
  * License: Apache License, Version 2.0
  * URL: <https://github.com/fumiyas/apache-mod-allowfileowner>
  * Blog: <http://fumiyas.github.io/>
  * Twitter: <https://twitter.com/satoh_fumiyasu>

Example
----------------------------------------------------------------------

```
LoadModule allowfileowner_module modules/mod_allowfileowner.so

<VirtualHost *>
  ## ...

  SetOutputFilter ALLOWFILEOWNER

  DocumentRoot /var/www
  <Directory /var/www>
    ## Content files must be owned by the following users
    AllowFileOwner foo bar
    ## ...
  </Directory>

  UserDir public_html
  <Directory /home/*/public_html>
    ## Content files must be owned by the individual user
    AllowFileOwnerInUserDir On
  </Directory>

  ## ...
</VirtualHost>
```

