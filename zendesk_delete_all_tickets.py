
from zdesk import Zendesk
import getopt
import sys

def usage():
    print """
        usage :
        zendesk_delete_all_tickets.py -d zdesk_domain -u zdesk_user -p zdesk_pass

        -d, --zdesk_domain    ZenDesk domain
        -u, --zdesk_user      ZenDesk user
        -p, --zdesk_pass      ZenDesk password
        -?, --help            Print this message
        """

if __name__ == '__main__':

    zdesk_domain = None
    zdesk_user = None
    zdesk_pass = None

    # parse input parameters
    try:
        opts, args = getopt.getopt(sys.argv[1:], "d:u:p:?", ["zdesk_domain=", "zdesk_user=", "zdesk_pass=", "help"])
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
        elif o in ("-?", "--help"):
            usage()
            sys.exit(2)
        else:
            assert False, "unhandled option"

    if zdesk_domain == None or zdesk_domain == None or zdesk_pass == None:
        print "Some parameters are missed"
        usage()
        sys.exit(1)

    zendesk = Zendesk(zdesk_domain, zdesk_user, zdesk_pass)
    while True:
        ticket_ids = None
        tickets = zendesk.tickets_list()
        ticket_ids = ",".join([str(ticket['id']) for ticket in tickets['tickets']])
        if ticket_ids:
            zendesk.tickets_destroy_many(ticket_ids)
        else:
            break