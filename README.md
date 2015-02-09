easy_install --upgrade google-api-python-client  
easy_install --upgrade python-gflags  
easy_install --upgrade httplib2  
easy_install --upgrade simplejson
easy_install --upgrade zdesk

##Enable the Gmail API
To enable Gmail API follow the steps: https://developers.google.com/gmail/api/quickstart/quickstart-python#step_1_enable_the_gmail_api.  
Download **client_secret.json** and put it next to migrate.py.

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
  
##Logging
Logs are stored in `gmail_zdesk_migration.log` file
