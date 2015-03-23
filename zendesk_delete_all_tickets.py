
from zdesk import Zendesk, ZendeskError
import getopt
import sys
import time

def usage():
    print """
        usage :
        zendesk_delete_all_tickets.py -d zdesk_domain -u zdesk_user -p zdesk_pass [-t tag]

        -d, --zdesk_domain    ZenDesk domain
        -u, --zdesk_user      ZenDesk user
        -p, --zdesk_pass      ZenDesk password
        -t, --tag             ZenDesk tag
        -?, --help            Print this message
        """

def group(iterable, count):
    return map(None, *[iter(iterable)]*count)

if __name__ == '__main__':

    zdesk_domain = None
    zdesk_user = None
    zdesk_pass = None
    zdesk_tag = None

    # parse input parameters
    try:
        opts, args = getopt.getopt(sys.argv[1:], "d:u:p:t:?", ["zdesk_domain=", "zdesk_user=", "zdesk_pass=", "zdesk_tag", "help"])
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
        elif o in ("-t", "--zdesk_tag"):
            zdesk_tag = a
        elif o in ("-?", "--help"):
            usage()
            sys.exit(2)
        else:
            assert False, "unhandled option"

    if zdesk_domain == None or zdesk_domain == None or zdesk_pass == None or zdesk_tag == None:
        print "Some parameters are missed"
        usage()
        sys.exit(1)

    zendesk = Zendesk(zdesk_domain, zdesk_user, zdesk_pass)

    tickets = []
    start_time = 1
    count = 1000

    while count == 1000:
        try:
            response = zendesk.incremental_tickets_list(start_time=start_time)
            tickets_filtered = filter(lambda x: x['status'] != 'deleted', response['tickets'])
            #print len(tickets_filtered)
            start_time = response['end_time']
            count = response['count']
            tickets.extend(tickets_filtered)
            time.sleep(7)
            #print start_time
        except ZendeskError, e:
            print 'ERROR: ' + type(Exception(e)).__name__ + ' ' + str(e)

    ticket_ids_str = ''
    if tickets:
        if zdesk_tag is not None:
            tickets = filter(lambda x: zdesk_tag in x['tags'], tickets)
        ticket_ids = set(x['id'] for x in tickets)

        for tickets_ids_part in group(ticket_ids,100):
            tickets_ids_part = filter(lambda x: x, tickets_ids_part)
            ticket_ids_str = ','.join(str(x) for x in tickets_ids_part)
            zendesk.tickets_destroy_many(ticket_ids_str)