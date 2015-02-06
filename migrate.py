import httplib2
import json
import base64
import logging
import traceback
import sys
import getopt

from apiclient.discovery import build
from oauth2client.client import flow_from_clientsecrets
from oauth2client.file import Storage
from oauth2client.tools import run
from zdesk import Zendesk
from datetime import datetime
from mail_processing import *

END_USER_NAME = 'user'
STATUS = 'solved'
TAGS = 'import'
MAX_ATTACHMENT_SIZE = 2 * 1024 * 1024 * 1.37

REPLY_PATTERNS = [
    '^.?On .*wrote:',
    '^From: .*\r\nSent: .*',
    '^From: .*\r\nTo: .*',
    '^From: .*\r\nDate: .*',
    '^Von: .*\r\nGesendet: .*',
]

FORWARD_MESSAGES = [
    # apple mail forward
    'Begin forwarded message',
    # gmail/evolution forward
    'Forwarded [mM]essage',
    # outlook
    'Original [mM]essage',
]

FORWARD_PATTERNS = [
    '^________________________',
] + ['^---+ ?%s ?---+' % p for p in FORWARD_MESSAGES] \
  + ['^%s:' % p for p in FORWARD_MESSAGES]


COMPILED_PATTERNS = [re.compile(regex, flags=re.MULTILINE|re.DOTALL) for regex in REPLY_PATTERNS + FORWARD_PATTERNS]

# Path to the client_secret.json file downloaded from the Developer Console
CLIENT_SECRET_FILE = 'client_secret.json'

# Check https://developers.google.com/gmail/api/auth/scopes for all available scopes
OAUTH_SCOPE = 'https://www.googleapis.com/auth/gmail.readonly'

# Location of the credentials storage file
STORAGE = Storage('gmail.storage')

def ticket_import(zendesk, requester_id, assignee_id, subject, tags, status, created_at, updated_at, comments):
    new_ticket = {
        "ticket": {
            "requester_id": requester_id,
            "assignee_id": assignee_id,
            "subject": subject,
            "tags": tags,
            "status": status,
            "comments": comments,
            "created_at": created_at,
            "updated_at": updated_at
        }
    }
    return zendesk.imports_ticket(data=new_ticket, complete_response=True)

def get_body(parts):
    for part in parts:
        if part.is_body.startswith('text'):
            payload, used_charset = decode_text(part.payload, part.charset, 'auto')
            #print payload.encode('UTF-8')
            return payload
    return None

def quote(text):
    #lines = text.split('\n')
    #unquoted = ''

    #for n in xrange(len(lines)):
    #    if not(lines[n].strip().startswith('>') and (n == len(lines) or lines[n+1].strip().startswith('>'))):
    #        unquoted += lines[n] + '\n'

    for regex in COMPILED_PATTERNS:
        match = re.search(regex, text)
        if match:
            #print 'Matched text=%s' % match.group()
            text = text[0:match.start()]

    return text

def upload_attachments(zendesk, parts):
    token = None
    for part in parts:
        if part.filename is not None and len(part.payload) < MAX_ATTACHMENT_SIZE:
            if token is None:
                query = {'filename': part.filename}
            else:
                query = {'filename': part.filename, 'token': token}
            response = zendesk.upload_create(data=part.payload, query=query, complete_response=True, mime_type=part.type)
            token = response['content']['upload']['token']
    return token

def convert_date(email_date):
    date = email.utils.parsedate_tz(email_date) #TODO check time zone
    timestamp = email.utils.mktime_tz(date)
    return datetime.fromtimestamp(timestamp).isoformat()

def thread_import(gmail_service, zendesk, thread):
    messages = gmail_service.users().threads().get(userId='me', id=thread['id'], format='metadata').execute()
    #print json.dumps(messages, sort_keys=True, indent=4)

    created_at = None
    updated_at = None
    requester_id = None
    assignee_id = None
    subject = None
    comments = []

    thread_subject = None
    #logging.info(messages)
    for header in messages['messages'][0]['payload']['headers']:
         if header['name'] == 'Subject':
            thread_subject = header['value']
            break

    #Skip threads with one email
    if len(messages['messages']) == 1:
        logging.warn('Thread ID: %s "%s" with one email is skipped' % (thread['id'], thread_subject))
        return True
    else:
        logging.info('Thread ID: %s "%s"' % (thread['id'], thread_subject))

    for (i, message) in enumerate(messages['messages']):
        message = gmail_service.users().messages().get(userId='me', id=message['id'], format='raw').execute()
        raw = base64.urlsafe_b64decode(message['raw'].encode('UTF-8'))
        msg = email.message_from_string(raw)
        parts = get_mail_contents(msg)

        email_from = getmailaddresses(msg, 'from')
        #skip failure messages
        #if email_from[0][1] == 'MAILER-DAEMON@mail1.intellij.net':
        #    message_count =+ 1
        #    continue
        #email_from = ('', '') if not email_from else email_from[0]
        email_to = getmailaddresses(msg, 'to')
        #email_to = ('', '') if not email_to
        email_cc = getmailaddresses(msg, 'cc')

        value = get_body(parts)
        if i != 0 or i != len(messages['messages'])-1:
            value = quote(value)

        if (value is None) or (value.strip() == ''):
            value = '<Empty>'
        date = convert_date(getmailheader(msg.get('Date', '')))

        #add email_from, email_to, email_cc addresses to ZenDesk ticket body
        value = '\n' + value
        if email_cc:
            value = 'CC: ' + ", ".join('"%s" <%s>' % tup for tup in email_cc) + '\n' + value
        if email_to:
            value = 'To: ' + ", ".join('"%s" <%s>' % tup for tup in email_to) + '\n' + value

        author_id = zendesk_users.get(email_from[0][0])

        if author_id is None:
            author_id = zendesk_users.get(END_USER_NAME)
            value = 'From: ' + ", ".join('"%s" <%s>' % tup for tup in email_from) + '\n' + value

        if i is 0:
            requester_id = zendesk_users.get(END_USER_NAME)
            subject = getmailheader(msg.get('Subject', ''))
            created_at = date
            logging.info('Subject: %s' % (subject))

        logging.info('Message ID: %s' % (message['id']))

        updated_at = date

        attachments = upload_attachments(zendesk, parts)

        comment = {'author_id': author_id, 'value': value, "created_at": date, "uploads": attachments}
        comments.append(comment)

    ticket_import(zendesk, requester_id, assignee_id, subject, TAGS, STATUS, created_at, updated_at, comments)
    return True

def usage():
    print """
        usage :
        migrate.py -d zdesk_domain -u zdesk_user -p zdesk_pass -l gmail_label

        -d, --zdesk_domain    ZenDesk domain
        -u, --zdesk_user      ZenDesk user
        -p, --zdesk_pass      ZenDesk password
        -l, --gmail_label     Gmail label
        -?, --help            Print this message
        """

if __name__ == '__main__':

    zdesk_domain = None
    zdesk_user = None
    zdesk_pass = None
    gmail_label = None

    # parse input parameters
    try:
        opts, args = getopt.getopt(sys.argv[1:], "d:u:p:l:?", ["zdesk_domain=", "zdesk_user=", "zdesk_pass=", "gmail_label=", "help"])
    except getopt.GetoptError as err:
        print str(err)
        usage()
        sys.exit(2)

    for o, a in opts:
        if o in ("-d", "--zdesk_domain"):
            zdesk_domain = a
        elif o in ("-u", "--zdesk_user"):
            zdesk_user = a
        elif o in ("-p", "--zdesk_pass"):
            zdesk_pass = a
        elif o in ("-l", "--gmail_label"):
            gmail_label = a
        elif o in ("-?", "--help"):
            usage()
            sys.exit(2)
        else:
            assert False, "unhandled option"

    if zdesk_domain == None or zdesk_domain == None or zdesk_pass == None or gmail_label == None:
        print "Some parameters are missed"
        usage()
        sys.exit(1)

    reload(sys)
    sys.setdefaultencoding("utf-8")

    logging.basicConfig(filename='gmail_zdesk_migration.log', level=logging.INFO, format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
    google_logger = logging.getLogger('googleapiclient.discovery')
    google_logger.setLevel(logging.WARN)
    logging.info('Import started')

    # Manually creating a new connection object
    zendesk = Zendesk(zdesk_domain, zdesk_user, zdesk_pass)
    zendesk_users = dict([(item['name'], item['id']) for item in zendesk.users_list()['users']])

    # Start the OAuth flow to retrieve credentials
    flow = flow_from_clientsecrets(CLIENT_SECRET_FILE, scope=OAUTH_SCOPE)
    http = httplib2.Http()

    # Try to retrieve credentials from storage or run the flow to generate them
    credentials = STORAGE.get()
    if credentials is None or credentials.invalid:
        credentials = run(flow, STORAGE, http=http)

    # Authorize the httplib2.Http object with our credentials
    http = credentials.authorize(http)

    # Build the Gmail service from discovery
    gmail_service = build('gmail', 'v1', http=http)
    page_token = None

    while True:
        try:
            # Retrieve a page of threads
            threads = gmail_service.users().threads().list(userId='me', labelIds=gmail_label, pageToken=page_token).execute()
            page_token = threads.get('nextPageToken')

            if threads['threads']:
                for thread in threads['threads']:
                    try:
                        thread_import(gmail_service, zendesk, thread)
                    except Exception, e:
                        logging.error('ERROR: thread_id ' + thread['id'] + ' ' + str(e))
        except Exception, e:
            logging.error('ERROR: page_token ' + page_token + ' ' + str(e))

        if page_token is None:
            break

    logging.info('Import finished')








