easy_install --upgrade google-api-python-client  
easy_install --upgrade python-gflags  
easy_install --upgrade httplib2  
easy_install --upgrade simplejson  

##Migrate threads from Gmail to ZenDesk:
  ```
  sudo migrate.py -d zdesk_domain -u zdesk_user -p zdesk_pass -l gmail_label

  -d, --zdesk_domain    ZenDesk domain  
  -u, --zdesk_user      ZenDesk user  
  -p, --zdesk_pass      ZenDesk password  
  -l, --gmail_label     Gmail label  
  -?, --help            Print this messag
  ```

To get the list of gmail labels use: https://developers.google.com/gmail/api/v1/reference/users/labels/list

##Delete all tickets in ZenDesk account:
  ```
  zendesk_delete_all_tickets.py -d zdesk_domain -u zdesk_user -p zdesk_pass

  -d, --zdesk_domain    ZenDesk domain  
  -u, --zdesk_user      ZenDesk user  
  -p, --zdesk_pass      ZenDesk password  
  -?, --help            Print this message
  ```
