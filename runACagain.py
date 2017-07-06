"""
This is a separate script produced alongside autoChecksum.py

This script re-runs the test against *ALL* tickets with priority 100.
(for example, we had many tickets which reported an error because
ralreplicas was not configured properly - this script helped clean
up)

It is intended that this be used with caution, particularly to the
`EXPECTED_NUM_ATTACHMENTS = 6` line which should be changed based on
the number of times autoChecksum has already been run against these
errors.

Currently, the script only updates the ticket if there are no errors.
(E.g. moving it from 25 to 75).

If there is an error, it only prints to the console rather than
logging to a file or reprinting the error to the ticket. (It is
assumed that the error is the same as the error already on the ticket
so there is no point re-printing to the ticket). 

Usage:
```
$ python3 -i runACagain.py
These are the tickets with priority 100:
[x, y, z, ...]
>>> runAgainstTheseTickets([x, z, ...])
```
The usage is manual to ensure that the user is sure they want to
do this.
"""


import autoChecksum
import requests
import re

def runAgainstTheseTickets(ticketsToTest):
    """Runs autoChecksum against each of the ids in a list. if
    int ids.
    This doesn't update the ticket unless no error occured.
    Returns a list of ids that failed.
    """
    failedTickets = []
    # NOTE this will need to be changed for a rerun with more than
    #      6 attachments.
    autoChecksum.EXPECTED_NUM_ATTACHMENTS = 6
    for id in ticketsToTest:
        # go through each id
        try:
            results = autoChecksum.getResultsOfTicketTest(id)
        except BaseException as ex:
            print(id, "ERROR, no results")
            print(ex)
            failedTickets.append(id)
            continue
        else:
            try:
                autoChecksum.addComment(id, results[0])
                # if the ticket could be resolved after action
                newPriority = 25 if results[1] else 75
                autoChecksum.editTicketPriority(id, newPriority)
            except BaseException as e:
                print(id, "ERROR, not updated")
                failedTickets.append(id)
                continue
            else:
                print(id, "priority to " + str(newPriority))
    return failedTickets

def getNewTicketsInChecksumQueueWithPriority100():
    """Returns a list of ticket ids for all the tickets with
    priority 100. To be rerun against."""
    query = "Status='new' AND Queue='Checksum' AND Priority='100'"
    url = autoChecksum.firstUrlPart + '/search/ticket?query=' + query
    response = requests.get(url, verify=False, cookies=autoChecksum.cookie)
    assert re.search(r'RT\/3.8.1 200 Ok\n', response.text) is not None
    return [int(x) for x in re.findall(r'(?<=\n)[0-9]*(?=:)', response.text)]

if __name__ == "__main__":
    ticketsToTest = getNewTicketsInChecksumQueueWithPriority100()
    print("These are the tickets priority 100:")
    print(ticketsToTest)
    if not autoChecksum.checkSshAgent:
        print("SSH AGENT ISN'T RUNNING, be prepared to enter your password...
               a lot!")
