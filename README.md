easy_install --upgrade google-api-python-client

easy_install --upgrade python-gflags

easy_install --upgrade httplib2

easy_install --upgrade simplejson

Initialize values:
LABEL = '' #get labels list: https://developers.google.com/gmail/api/v1/reference/users/labels/list

ZDESK_DOMAIN = 'https://.zendesk.com'
ZDESK_USER = 'user@gmail.com'
ZDESK_PASS = 'pass'

Migrate threads from Gmail to ZenDesk:
sudo python migrate.py

Delete tickets:
sudo python zendesk_delete_all_tickets.py
