easy_install --upgrade google-api-python-client  
easy_install --upgrade python-gflags  
easy_install --upgrade httplib2  
easy_install --upgrade simplejson  
easy_install --upgrade zdesk

Python 2.7

##Enable the Gmail API

To enable Gmail API follow the steps:  
	1.	Go to the [Google Developers Console](https://console.developers.google.com).  
	2.	Select a project, or create a new one.  
	3.	In the sidebar on the left, expand **APIs & auth**. Next, click **APIs**. In the list of APIs, make sure the status is **ON** for the Gmail API.  
	4.	In the sidebar on the left, select **Credentials**.  
	5.	**Create new Client ID** under the **OAuth** heading. Select **Installed application** and prees **Configure consent screen**.  
	6.	Select **Email address**, enter **Product name** and press **Save**. Select **Installed application**, type **Other** and press **Create Client ID**.  
	7.	Click **Download JSON** to save the **client_secret.json** and put it next to migrate.py.  
	
For more details see: https://developers.google.com/gmail/api/quickstart/quickstart-python#step_1_enable_the_gmail_api.  


##Migrate threads from Gmail to ZenDesk:
  ```
  migrate.py -d zdesk_domain -u zdesk_user -p zdesk_pass -l gmail_label

  -d, --zdesk_domain    ZenDesk domain  
  -u, --zdesk_user      ZenDesk user  
  -p, --zdesk_pass      ZenDesk password  
  -l, --gmail_label     Gmail label  
  -?, --help            Print this messag
  ```

To get the list of gmail labels use: https://developers.google.com/gmail/api/v1/reference/users/labels/list

##Delete all tickets in ZenDesk account:
  ```
  zendesk_delete_all_tickets.py -d zdesk_domain -u zdesk_user -p zdesk_pass -t zdesk_tag

  -d, --zdesk_domain    ZenDesk domain  
  -u, --zdesk_user      ZenDesk user  
  -p, --zdesk_pass      ZenDesk password 
  -t, --zdesk_tag       ZenDesk tag
  -?, --help            Print this message
  ```
  
##Logging
Logs are stored in `gmail_zdesk_migration.log` file
