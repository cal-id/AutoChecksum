#! /usr/local/bin/python3.5

###############################################################################
# PROBABLY DOESN'T WORK IN PYTHON2!
# -----------------------------------------------------------------------------
# If considering trying to run on python2.x, there were breaking changes
# including 'print' is now a function between 2.x and 3.x so be cautious.
# The python website states that all versions of python3.x are backward
# compatible. I have tested this on python 3.4 and 3.5.
###############################################################################

###############################################################################
# Other files required:
# -----------------------------------------------------------------------------
# NOTE: the below shell scripts probably require execute permissions
# - ./sshCat.sh           file
# - ./sshLs.sh            file
# - ./sshRalreplicas.sh   file
# - ./log/                folder
###############################################################################

###############################################################################
# Changes
# -----------------------------------------------------------------------------
# new version 29.11.2016 -> added check that ssh-agent is running
# this means that the script will no longer run if ssh-agent isn't running.
# ----
# new version 12.12.2016 -> changed ssh scripts to include
#         -o "StrictHostKeyChecking no"
# this means that 'are you sure that you want to connect (yes/no)' will not pop
# ----
# new version 31.01.2017 -> saw the boundary case for the first time so added
# some comments to make it clear why we logged the boundary case
# ----
# new version 21.04.2017 -> Error handle to ticket, sets ticket priority to 100
# also checks that python version is 3.
# ----
# new version 28.06.2017 -> Add EXPECTED_NUM_ATTACHMENTS global rather than
# hard coding to '5'
###############################################################################

###############################################################################
# How it works
# -----------------------------------------------------------------------------
#     The functions should be self explainatory. Lots of them are to do with
# getting/changing stuff from RT which is not longer needed but may be useful
# functionality in the future so I kept them. Each time the script is run,
# the function 'run()' is called which acts as a wrapper to all other calls so
# that exceptions are definitely caught and sent to the log file rather than to
# standard out.
#     There are a number of LIMITATIONS highlighted in comments. Mainly, it
# cannot deal with merged tickets because it may end up with a situation where
# it investigates one ticket and deletes a file from a different merged ticket.
###############################################################################

# get a library for http/https requests
# This module requires installation from pip. You can use pip's virtual
# environments to avoid conflicts with other programs using the same version of
# python
import requests

# get a library for using regular expressions
import re

# get the library for calling shell scripts
import subprocess

# get logging library
import logging

# get datetime for naming the log files
import datetime

import sys  # to check python version

import os  # to perform startup checks 
assert sys.version_info >= (3, 0)

# initiate logging
# Check if the log directory exists, if not create it
if not os.path.isdir("log"):
    os.mkdir("log")
logger = logging.getLogger('autoChecksum')
fileLogHandler = logging.FileHandler(('./log/'
                                      + str(datetime.datetime.now())
                                      + '.txt'), "w")
fileLogHandler.setLevel = logging.INFO
fileLogHandler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
logger.addHandler(fileLogHandler)
logger.setLevel(logging.INFO)
logger.debug('logging started')

# disable warnings for insecure https... Maybe comment this line for debug?
# insecure https happens using 'verify=False' (next line), the connection is
# encrypted but we can't be sure that the server we are connecting to is who
# we think they are.
requests.packages.urllib3.disable_warnings()

# If the script recieves a number of attachments per ticket that isn't this,
# it raises an error. Normally this should be set to 5. However, this script
# reports its results back to the ticket as an attachment so if you are trying
# to rerun this script semi manually against a ticket it has already processed,
# this global must be set.
# CHANGE WITH CAUTION: This is one of the main checks that the ticket hasn't
#                      been merged, without this check, errors could go
#                      missing through resolving only one part of a merged
#                      ticket.
EXPECTED_NUM_ATTACHMENTS = 5

# TODO: NEED NEW USERNAME AND PASSWORD WHEN LIVE
# post username and password to get cookie
# 'verify=False' ignores certificate authentication
USER_NAME = 'callum.iddon@stfc.ac.uk'
USER_PASSWORD = 'passHDci5'
cookieRequest = requests.post('https://helpdesk.gridpp.rl.ac.uk/',
                              verify=False, data={'user': USER_NAME,
                                                  'pass': USER_PASSWORD})

# store the url in a global variable, it is accessed often
firstUrlPart = 'https://helpdesk.gridpp.rl.ac.uk/REST/1.0/'

# cookieRequest.cookies['RT_SID_Gridpp.443'] is the cookie
# store the cookie dictionary under the name cookie
cookie = cookieRequest.cookies


# takes a response (string) and checks that it is the right version (bool)
# this makes it future proof (ie raises an error if the version of RT changes)
def isResponseExpected(response):
    if(re.search(r'((^Status:.*\n)|(^))RT\/3.8.1 200 Ok\n\n', response)
       is not None):
        if re.search(r'\n#.*', response):
            logger.warning("Response has a line with a # in it... this could "
                           "be an error message. Response: \n" + response)
        return True
    raise Exception("Unexpected response: \n" + response)
    return False


# takes a response (str) and checks that the ticket actually exists (bool)
# - incase wrong ticket id is supplied
def doesTicketExist(response):
    if re.search(r'\n# Ticket .* does not exist.\n', response):
        raise Exception("Ticket does not exist: \n" + response)
        return False

    return True


# takes a response (str) and checks that the attachment which was requested
# actually exists (bool)
def doesAttachmentExist(response):
    if re.search(r'\n# Invalid attachment id: [0-9]*\n', response):
        raise Exception("Attachment does not exist: " + response)
        return False

    return True


# takes a response (str) and checks that the comment or attachment recieved
def didCommentOrAttachmentWork(response):
    if(re.search(r'((^Status:.*\n)|(^))RT\/3.8.1 200 Ok\n\n', response) and
       re.search(r'\n\n# Message recorded\n', response)):
        return True
    return False


# checks that the response (str) is for the requested id (str)
# eg id 174002 returns 174000
# LIMITATION: doesn't work on merged tickets
def isIdSameInResponse(strId, response):
    search = re.search(r'\n\nid: ticket\/[0-9]*\/attachments\n', response)
    lengthOfExtra = 26  # 26 is the length of \n\nid: ticket//attachments\n
    if search is None:
        search = re.search(r'\n\nid: ticket\/[0-9]*', response)
        lengthOfExtra = 13
    span = search.span()
    length = span[1] - span[0] - lengthOfExtra
    # 13 is the length of \n\nid: ticket/
    responseId = response[span[0] + 13:span[0] + 13 + length]
    if responseId == strId:
        return True
    raise Exception(
        "Wrong id returned in response... ticket probably merged." + strId)
    return False


# gets ticket properties (dict) of ticket with id (int)
def getTicketProperties(id):
    strId = str(id)
    response = requests.get(firstUrlPart + 'ticket/' + strId + '/show',
                            verify=False, cookies=cookie)
    # initial checks
    if(not(isResponseExpected(response.text) and
       doesTicketExist(response.text))):
        return []
    if not isIdSameInResponse(strId, response.text):
        return []
    responseLines = response.text.splitlines()
    ticketProperties = {}
    # go through each line
    for i in responseLines:

        # split each line on the first ':'
        listPair = i.split(":", 1)

        # if there is a pair
        if len(listPair) == 2:

            if len(listPair[1]) > 1:
                # if the first character of the value is a space, remove it
                if listPair[1][0] == " ":
                    listPair[1] = listPair[1][1:]

            # add pair to the dictionary
            ticketProperties[listPair[0]] = listPair[1]

        # if there isn't a pair and it isn't an empty line and it isn't the
        # version line then its unrecognised
        elif (len(listPair) == 1 and listPair[0] != '' and
              listPair[0] != "RT/3.8.1 200 Ok"):
            logger.warning('Unrecognised line in ticket with no colon: ' +
                           listPair[0] + '. The id is: ' + strId)
    if ticketProperties['Queue'] != "Checksum":
        logger.warning("This ticket isn't in the checksum queue. ID: " + strId)
    return ticketProperties


# gets a list of ids (int) of hopefully 5 attachments from a ticket id (int)
def getTicketAttachments(id):
    strId = str(id)
    response = requests.get(firstUrlPart + 'ticket/' + strId + '/attachments',
                            verify=False, cookies=cookie)

    if isResponseExpected(response.text) and doesTicketExist(response.text):
        if not isIdSameInResponse(strId, response.text):
            return []

    else:
        return []

    ticketAttachments = []
    if len(re.findall(r'\nAttachments: ', response.text)) != 1:
        raise Exception(("Should be exactly one 'Attachments: ' in the "
                         "response for ticket id: ") + str(id))
        return []

    splitIndex = re.search(r'\nAttachments: ', response.text).span()[1]
    content = response.text[splitIndex:]
    contentLines = content.splitlines()
    for i in contentLines:
            if i != "":
                pair = i.split(": ", 1)
                if len(pair) == 2:
                    ticketAttachments.append(int(pair[0]))
                else:
                    raise Exception('Line did not split correctly: ' + i)
    return ticketAttachments


# gets the content of the attachment with the NOKs in it
# LIMITATION: Assumes that second attachment is the one with just NOK:/ - some
# don't have 5 because they are merged - 157108 (merged ticket)
def getTicketContent(i):
    strId = str(i)
    ticketAttachments = getTicketAttachments(i)
    if len(ticketAttachments) != EXPECTED_NUM_ATTACHMENTS:
        # LIMITATION: doesn't work with merged tickets
        raise Exception(('Unexpected length of ticket attachments at id: {}'
                         ' this probably means that this ticket has'
                         ' been merged so only some of it would be dealt '
                         'with...').format(i))
        return
    url = firstUrlPart + "ticket/{}/attachments/{}/content"
    response = requests.get(url.format(strId, ticketAttachments[1]),
                            verify=False, cookies=cookie)
    if not isResponseExpected(response.text):
        return ""
    if not doesAttachmentExist(response.text):
        return ""
    if("NOK: /" in response.text and
       "Checksum mismatches from " in response.text):
        return re.split(r"\nChecksum mismatches from ", response.text)[1]
    else:
        raise Exception(
            "'NOK: /' is not in the second attachment... Attachment: " +
            firstUrlPart + 'ticket/' + strId + '/attachments/' +
            str(ticketAttachments[1]) + '/content')
    return ""


# gets the summary of a ticket (dict) from a ticket with id (int)
# - Problems (int), Warnings (int), From (str)
def getTicketContentSummary(id):
    content = getTicketContent(id)
    lines = content.splitlines()

    summary = {}

    summary['From'] = lines[0].split(" attached", 1)[0]
    summary['Problems'] = int(lines[1].split(" Problems; ", 1)[0])
    summary['Warnings'] = int(lines[1].split(" Problems; ", 1)[1].split(
        " Warnings", 1)[0])
    return summary


# gets the NOKs of the content of a ticket (list) from a ticket with id (int)
def getTicketContentNOKs(id):
    content = getTicketContent(id)

    # get the contents of all lines that start 'NOK: '' and end with either a
    # return or an end of string
    stringNOKs = re.findall(r"(?<=\nNOK: ).*(?=\n|$)", content)
    listOfNOKs = []

    for stringNOK in stringNOKs:
        NOK = {}

        # find first ( from end of string and split on it
        split1 = [x[::-1] for x in stringNOK[::-1].split("(", 1)[::-1]]

        # find first ', ' from end of file names and split on it
        #  - this is because second file path cannot have a space in but first
        #    theoretically could
        split2 = [x[::-1] for x in split1[0][::-1].split(" ,", 1)[::-1]]
        # Note that the reverse split means that the comma and space are
        # reversed
        NOK["firstLink"] = split2[0]
        NOK["secondLink"] = split2[1]
        # 174001 has a checksum of 1
        # 621404 has a checksum that is 'None'
        # 175202/622789 checksum of 6 digits not 8 => no leading 0s
        split3 = split1[1].split(", ", 1)
        split4 = split3[1].split(", ", 1)
        split5 = split4[1].split(")", 1)
        # removes the initial and trailing quotes from a string
        # (normally second two checksums)

        def chopOffQuotes(str):
            if str[0] == "'":
                str = str[1:]
            if str[-1] == "'":
                str = str[0:-1]
            return str
        NOK['checksum1'] = chopOffQuotes(split3[0])
        NOK['checksum2'] = chopOffQuotes(split4[0])
        NOK['checksum3'] = chopOffQuotes(split5[0])
        listOfNOKs.append(NOK)
    return listOfNOKs


# gets the disk server from a properties (dict) of a ticket
def getDiskServer(properties):
    try:
        diskserver1 = properties['Creator'].split("@", 1)[1]
    except IndexError:
        logger.warning("Diskserver can't be found in Creator")
    try:
        diskserver2 = properties['Requestors'].split("@", 1)[1]
    except IndexError:
        logger.warning("Diskserver can't be found in Requestors")
    try:
        diskserver3 = properties['Subject'].split('host ', 1)[1]
    except IndexError:
        logger.warning("Diskserver can't be found in Subject")
    if diskserver1 == diskserver2:
        if diskserver1 == diskserver3:
            return diskserver1
        else:
            logger.warning("Subject is probably wrong")
            return diskserver1
    else:
        logger.warning("Creator and requestors do not match")
        if diskserver3 == diskserver1:
            logger.warning("Requestors is probably wrong")
            return diskserver3
        if diskserver3 == diskserver2:
            logger.warning("Creator is probably wrong")
            return diskserver3
        raise Exception("None of the possible diskservers match")


# gets a (list) of ids (int) of tickets in the checksum queue
def getTicketsInChecksumQueue():
    url = firstUrlPart + '/search/ticket?query=Queue=%27Checksum%27'
    response = requests.get(url, verify=False, cookies=cookie)
    assert re.search(r'RT\/3.8.1 200 Ok\n', response.text) is not None
    return [int(x) for x in re.findall(r'(?<=\n)[0-9]*(?=:)', response.text)]


# gets a (list) of ids (int) of tickets in the checksum queue marked as 'new'
def getNewTicketsInChecksumQueue():
    url = (firstUrlPart
           + '/search/ticket?query=Queue=%27Checksum%27ANDStatus=%27New%27')
    response = requests.get(url, verify=False, cookies=cookie)
    assert re.search(r'RT\/3.8.1 200 Ok\n', response.text) is not None
    return [int(x) for x in re.findall(r'(?<=\n)[0-9]*(?=:)', response.text)]


def getNewTicketsInChecksumQueueWithPriority50():
    query = "Status='new' AND Queue='Checksum' AND Priority='50'"
    response = requests.get(firstUrlPart + '/search/ticket?query=' + query,
                            verify=False, cookies=cookie)
    assert re.search(r'RT\/3.8.1 200 Ok\n', response.text) is not None
    return [int(x) for x in re.findall(r'(?<=\n)[0-9]*(?=:)', response.text)]


# gets a (list) of all ids (int) of tickets in the support queue that should be
# in the checksum queue
def getNewTicketsForChecksumInSupportQueue():
    query = ("Status='new' AND "
             "Requestor.EmailAddress LIKE 'root@' AND "
             "Subject LIKE 'Checksum Mismatch on host' AND "
             "Queue='Support'")
    response = requests.get(firstUrlPart + '/search/ticket?query=' + query,
                            verify=False, cookies=cookie)
    assert re.search(r'RT\/3.8.1 200 Ok\n', response.text) is not None
    return [int(x) for x in re.findall(r'(?<=\n)[0-9]*(?=:)', response.text)]


# changes the status of a ticket with id (int) to newStatus (str)
def editTicketStatus(id, newStatus):
    strId = str(id)
    content = 'Status: ' + newStatus
    print(requests.post(firstUrlPart + 'ticket/' + strId + '/edit',
          verify=False, data={'content': content}, cookies=cookie).text)


# changes the queue of a ticket with id (int) to newQueue (str)
def editTicketQueue(id, newQueue):
    strId = str(id)
    content = 'Queue: ' + newQueue
    response = requests.post(firstUrlPart + 'ticket/' + strId + '/edit',
                             verify=False, data={'content': content},
                             cookies=cookie).text
    assert (re.search(r'\n# Ticket ' + str(id) + ' updated.\n', response)
            is not None)


# changes the prioirty of ticket with id (int) to newPriority (int)
def editTicketPriority(id, newPriority):
    strId = str(id)
    content = 'Priority: ' + str(newPriority)
    response = requests.post(firstUrlPart + 'ticket/' + strId + '/edit',
                             verify=False, data={'content': content},
                             cookies=cookie).text
    assert (re.search(r'\n# Ticket ' + str(id) + ' updated.\n', response)
            is not None)


# adds a comment (str) to ticket with id (int)
def addComment(id, comment):
    strId = str(id)
    # replace all '/n' with '/n '
    fixedComment = re.sub(r'\n(?=[^ ])', "\n ", comment)
    content = '''id: ''' + strId + '''
Action: comment
Text: ''' + fixedComment
    return didCommentOrAttachmentWork(
        requests.post(
            firstUrlPart + 'ticket/' + strId + '/comment', verify=False,
            data={'content': content}, cookies=cookie).text)


# adds both a comment (str) and attachment (str) with name (str) to a ticket
# with id (int)
def addCommentAndAttachment(id, attachment, attachmentName='untitled',
                            comment=''):
    strId = str(id)
    # replace all '/n' with '/n '
    fixedComment = re.sub(r'\n(?=[^ ])', "\n ", comment)
    content = '''id: ''' + strId + '''
Action: comment
Text: ''' + fixedComment + '''
Attachment: ''' + attachmentName
    return didCommentOrAttachmentWork(
        requests.post(
            firstUrlPart + 'ticket/' + strId + '/comment', verify=False,
            data={'content': content}, files={'attachment_1': attachment},
            cookies=cookie).text)


# adds an attachment from filePath (str) to a ticket with id (int)
def addAttachmentFromFile(id, filePath):
    with open(filePath, 'r') as file:
        attachment = file.read()
        attachmentName = filePath.split("/")[-1]
        return addCommentAndAttachment(id, attachment,
                                       attachmentName=attachmentName,
                                       comment=('Attaching a test shell script'
                                                ' using the REST api...'))


# checks that ssh-agent is running and has a key. Without this check then it
# could prompt for password as a fallback
def checkSshAgent():
    try:
        subprocess.check_output(["ssh-add", "-l"])  # try to list the keys
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            # if the returncode is 1 then 'The agent has no identities'
            logger.exception(("The ssh-agent is running but there are no keys,"
                              " try running 'ssh-add'"))
        if e.returncode == 2:
            # if the returncode is 2 then 'Could not open a connection to your
            # authentication agent'
            logger.exception(
                "The ssh-agent is not running. Try running 'eval `ssh-agent`'")
        return False
    return True


# Checks that the wrapper scripts ssh*.sh are executable
def checkScriptsExecutable():
    for script in ("sshRalreplicas.sh", "sshCat.sh", "sshLs.sh"):
        if not os.access(script, os.X_OK):
            logger.exception("The script '{}' must be executable. "
                             "Use 'chmod 755 {}'".format(script, script))
            return False
    return True


# input a ticket (dict) and return whether it can be resolved overall and
# whether each NOK can be resolved
# returns flagCanResolveTicket=True IF THE FILE DOESNT EXIST - THIS MEANS
# THAT IT HAS BEEN CLEANED UP!
def canResolveByTest1(ticket):
    flagCanResolveTicket = True
    for index, nok in enumerate(ticket['NOKs']):
        physicalFilePath = ticket['NOKs'][index]["secondLink"]
        logger.debug(
            "ssh into " + ticket['diskserver'] + " ls for " + physicalFilePath)
        try:
            subprocess.check_output(
                ['./sshLs.sh', ticket['diskserver'], physicalFilePath],
                stderr=subprocess.STDOUT)
            # stderr = subprocess.STOUT sends the error down the same route as
            # the output
        except subprocess.CalledProcessError as e:
            if e.returncode == 2:
                ticket['action'][index] += ('(Test1) Do nothing, physical file'
                                            ' no longer exists. ')
                ticket['results'][index][0] = (
                    'File no longer exists on disk server')
            else:
                raise Exception(("Expected sshLs to have a return code 2 if it"
                                 " fails... Output: ") + str(e.output))
        except:
            raise Exception("Unexpected return from bash")
        else:
            flagCanResolveTicket = False
            ticket['results'][index][0] = 'File does exist on disk server'
        logger.debug((" Test1: ticket {}: NOK#{} resolvable?: {}"
                      ).format(ticket['id'], index, ticket['resolved'][index]))
    return (flagCanResolveTicket, ticket)


# input a ticket (dict) and return the stager associated with that ticket's
# diskserver.
def getStager(ticket):
    logger.debug(("ssh into {} cat for /etc/castor/castor.conf"
                  ).format(ticket['diskserver']))
    try:
        output = subprocess.check_output(
            ['./sshCat.sh', ticket['diskserver'], "/etc/castor/castor.conf"])
    except:
        raise Exception("Unexpected return from bash")
    else:
        decodedOutput = output.decode()
        parseStager = re.findall(
            r"(?<=\nSTAGER     HOST ).*(?=\n)", decodedOutput)
        if len(parseStager) == 1 and parseStager[0] != "":
            return parseStager[0]
        else:
            raise Exception("No (or multiple) match for 'STAGER    HOST'")


# input a ticket (dict) and return whether the ticket can be resolved and
# whether each individual NOK can be resolved
def canResolveByTest2(ticket):
    flagCanResolveTicket = True
    stager = getStager(ticket)
    for index, nok in enumerate(ticket['NOKs']):
        physicalFilePath = ticket['NOKs'][index]["secondLink"]
        logicalFilePath = ticket['NOKs'][index]["firstLink"]
        logger.debug("ssh into " + stager + " ralreplicas for " +
                     logicalFilePath)
        try:
            output = subprocess.check_output(
                ['./sshRalreplicas.sh', stager, logicalFilePath],
                stderr=subprocess.STDOUT)
            # If there is an error, ral replicas returns exit code 0 and
            # prints an error!
        except:
            flagCanResolveTicket = False
            raise Exception("Unexpected return from bash")
        else:
            decodedOutput = output.decode()
            thisRegex = (r"(?<=DISKCOPY_STAGED      "
                         r")[^:\n]*:\/exportstage\/castor[^ ]*@[^ ]*(?= )")
            parseDiskcopy = re.findall((thisRegex), decodedOutput)
            if len(parseDiskcopy) == 1 and parseDiskcopy[0] != "":
                castorPointsTo = parseDiskcopy[0]
                diskServerWithPhysicalFilePath = (ticket['diskserver'] + ":" +
                                                  physicalFilePath)
                if castorPointsTo != diskServerWithPhysicalFilePath:
                    ticket['results'][index][1] = ('Stager points to a '
                                                   'different physical file '
                                                   'path.')
                    ticket['resolved'][index] = True
                    ticket['action'][index] += \
                        ('(Test2) Delete the physical file. (If it even exists'
                         ' - check Test1 results).')
                else:
                    flagCanResolveTicket = False
                    ticket['results'][index][1] = ('Stager points to the same '
                                                   'physical file path.')

            elif (re.search((r'((\n|^)Error : invalid argument "[0-9]*")|'
                             r'(\n|^)File \([0-9]*\) not in ns \/ not in '
                             'stager'),
                            decodedOutput) is not None):
                ticket['results'][index][1] = ('Stager has no record of this '
                                               'logical file path.')
                ticket['resolved'][index] = True
                ticket['action'][index] += ('(Test 2) Delete the physical '
                                            'file. (If it even exists - check '
                                            'Test1 results).')

            elif (re.search(r'(\n|^)File .*not in stager\n',
                            decodedOutput) is not None
                  and re.search(r'\nFile migrated\n',
                                decodedOutput) is not None
                  and re.search(r'\nTape fileclass with \d* cop',
                                decodedOutput) is not None):
                ticket['results'][index][1] = ('Stager thinks this logical '
                                               'file is on tape so does not '
                                               'point at this physical file')
                ticket['resolved'][index] = True
                ticket['action'][index] += ('(Test 2) Delete the physical '
                                            'file. (If it even exists - check '
                                            'Test1 results).')

            else:
                # LIMITATION: doesn't look for two DISKCOPY_STAGED
                # - rare case apparently
                raise Exception(("couldn't understand ralreplicas command: " +
                                 "./sshRalreplicas.sh {} {}"
                                 ).format(stager, logicalFilePath))
                flagCanResolveTicket = False
        logger.debug((" Test2: ticket {}: NOK#{} resolvable?: {}"
                      ).format(ticket['id'], index, ticket['resolved'][index]))
    return (flagCanResolveTicket, ticket)


# go through the different tests on a ticket with id (int) and check if the
# ticket can be resolved
def goThroughTicket(id):
    logger.info("Going through ticket with id: " + str(id))
    properties = getTicketProperties(id)
    if not (properties['Status'] == "new" or properties['Status'] == "open"):
        logger.warning("This ticket is neither new nor open: " + str(id))
    ticket = {
        'NOKs': getTicketContentNOKs(id),
        'diskserver': getDiskServer(properties),
        'id': id

    }
    ticket['resolved'] = [False for x in ticket['NOKs']]
    ticket['results'] = [[None, None] for x in ticket['NOKs']]
    ticket['action'] = ['' for x in ticket['NOKs']]

    flagCanResolveTicket = False

    test1 = canResolveByTest1(ticket)
    # flagCanResolveTicket = True if test1[0] == True else flagCanResolveTicket
    ticket = test1[1]

    test2 = canResolveByTest2(ticket)
    # use test2's result and log below if they differ
    # test1            test2                       action
    # file no exist    stager points to different  resolve
    # file no exist    stager points to same       don't resolve -> see below
    # file exists      stager points to different  resolve (delete file)
    # file exists      stager points to same       don't resolve

    # so the overall results come from the results of test2
    # but we should log if stager points elsewhere
    flagCanResolveTicket = test2[0]

    if test1[0] and not test2[0]:
        # if file no longer exists but stager still points to it then something
        # seriously bad has gone wrong...
        logger.warning("This is a boundary case, test1 says resolve the "
                       "ticket, test2 says don't resolve!")
    ticket = test2[1]
    return (flagCanResolveTicket, ticket)


# Gets the result of both the tests on the ticket with id (int)
def getResultsOfTicketTest(id):
    resultOfTests = goThroughTicket(id)
    resultOfTicket = ("THIS TICKET CAN BE RESOLVED\n\n"
                      if resultOfTests[0]
                      else "THIS TICKET CANNOT BE RESOLVED\n\n")
    ticket = resultOfTests[1]
    checkFineToResolve = True
    for index, nok in enumerate(ticket['NOKs']):
        resultOfTicket = """NOK #{}
\tLogical: {}
\tPhysical: {}
\tTest1: {}
\tTest2: {}
\tAction: {}
\tResolvable?: {}
\t
"""
        action = (str(ticket['action'][index])
                  if str(ticket['action'][index]) != ''
                  else 'Needs manual investigation')
        resultOfTicket = resultOfTicket.format(index,
                                               nok['firstLink'],
                                               nok['secondLink'],
                                               ticket['results'][index][0],
                                               ticket['results'][index][1],
                                               action,
                                               ticket['resolved'][index])
        if ticket['resolved'][index] is False:
            checkFineToResolve = False
    if checkFineToResolve != resultOfTests[0]:
        raise Exception("The results of the test are inconsistent... "
                        "watch out...")
    return(resultOfTicket, resultOfTests[0])


def printResultsOfTicketTest(id):
    result = getResultsOfTicketTest(id)
    print(result[0])


def run():
    logger.info("Run started")
    # Move all tickets of this nature from support to checksum
    try:
        supportQueue = getNewTicketsForChecksumInSupportQueue()
        logger.info("Found " + str(len(supportQueue)) +
                    " checksum tickets in support queue")
    except BaseException as e:
        logger.exception(e)
        # don't worry if this fails... non vital... but tell the logs
    else:
        for id in supportQueue:
            try:
                editTicketQueue(id, 'Checksum')
            except AssertionError:
                logger.warning("Couldn't move ticket " + str(id) +
                               " to the checksum queue")
            else:
                logger.info("Moved ticket " + str(id) +
                            " to the checksum queue")
    # now get a list of all the tickets in the checksum queue
    ticketsToTest = getNewTicketsInChecksumQueueWithPriority50()
    if len(ticketsToTest) != 0:
        # if there are any tickets to test, check an ssh key is loaded
        if not checkSshAgent():
            # if there is no key then end the run and exit (checkSshAgent has
            # already logged this)
            # for the moment print this to console because it is so fundamental
            # TODO: is this needed when the script is run by cronjob?
            print("ssh agent check failed")
            return
        if not checkScriptsExecutable():
            # if the scripts are not executable then exit because they are 
            # fundamental
            print("Scripts not executable, check logs")
            return
    for id in ticketsToTest:
        # go through each id
        try:
            results = getResultsOfTicketTest(id)
        except BaseException as ex:
            # If there is an error here then print it to the ticket
            addComment(id, ("An Error Occurred While Processing Ticket:\n"
                            "{}").format(ex))
            editTicketPriority(id, 100)
            logger.exception(ex)
        else:
            addComment(id, results[0])
            # if the ticket could be resolved after action
            newPriority = 25 if results[1] else 75
            try:
                editTicketPriority(id, newPriority)
            except AssertionError as e:
                logger.exception(e)
            else:
                logger.info(
                    "Changed ticket " + str(id) + " priority to " +
                    str(newPriority))
    logger.info("Run finished")


# the function which is called routinely to start the run
# this overall functon is used to catch any unexpected errors
def go():
    try:
        run()
    except BaseException as e:
        logger.exception(e)
        # in this case, it was unpredicted so raise the exception
        raise e


if __name__ == "__main__":
    # start everything going
    go()

###############################################################################
# TESTING
# anything below here can be ignored, only used for debug
###############################################################################

# List of NOK tickets to test on -> when I was testing, these were a
# batch of unprocessed tickets. Unfortunaately they have been processed by this
# script now. I suggest that you comment out the restriction on tickets without
# five attachments (LIMITATION about merged tickets) because these tickets will
# now have at least 6 attachments. This means that you can use these as a
# testing set again.
listOfTicketsToTest = [174001, 174022, 174152, 174828, 174851, 174870, 174872,
                       174895, 174903, 174980, 174994, 175009, 175038, 175039,
                       175041, 175115, 175166, 175170, 175202, 175203, 175207,
                       175312, 175330, 175343, 175346, 175347, 175349, 175350,
                       175369, 175370, 175371, 175373, 175417, 175470, 175492,
                       175596, 175621, 175622, 175637, 175644, 175646, 175652,
                       175673, 175702, 175727, 175728, 175729, 175730, 175765,
                       175768, 175769, 175770, 175771, 175780, 175781, 175783,
                       175808, 175812, 175814, 175815, 175817, 175818, 175823,
                       175832, 175834, 175851, 175852, 175861, 175863, 175866,
                       175867, 175868, 175869, 175870, 175871, 175872, 175873,
                       175877, 175878, 175879, 175884, 175886, 175887, 175904,
                       175905, 175906]


# should print the content of the attachments of all tickets in list of tickets
# to test
def TESTContentOfAttachments():
    for testTicket in listOfTicketsToTest:
        strId = str(testTicket)
        attachments = getTicketAttachments(testTicket)
        print("Ticket " + str(testTicket) + " has " + str(len(attachments)) +
              " attachments.")
        count = 0
        for attachment in attachments:
            count += 1
            if count == 3:
                print("")
                print("ATTACHMENT 3 NOT SHOWN BECAUSE IT IS HUGE")
                print("")
                continue
            response = requests.get((firstUrlPart + 'ticket/' + strId +
                '/attachments/' + str(attachment) + '/content'), verify=False,
                cookies=cookie)
            print("")
            print("attachment #" + str(count))
            print("")
            print(response.text)
            print("")


# tests that properties can be read from all tickets
def TESTproperties():
    for testTicket in listOfTicketsToTest:
        properties = getTicketProperties(testTicket)
        print("Ticket " + str(testTicket) + " has these properties")
        for property in properties:
            print(" -" + str(property) + " = " + properties[property])
        print()


# tests that summaries can be read from all tickets
def TESTSummary():
    locationOfAWarning = False
    for testTicket in listOfTicketsToTest:
        summary = getTicketContentSummary(testTicket)
        print("Ticket " + str(testTicket) + " has summary")
        for item in summary:
            print(" -" + str(item) + " = " + str(summary[item]))
        if summary['Warnings'] > 0:
            locationOfAWarning = testTicket

        print()
    if locationOfAWarning:
        print("There is actually a ticket with a warning: " + str(testTicket))


# tests that NOKs can be got from each ticket
def TESTNOKs():
    for testTicket in listOfTicketsToTest:
        listOfNOKs = getTicketContentNOKs(testTicket)
        print("Ticket " + str(testTicket) + " has these NOKs")
        count = 0
        for NOK in listOfNOKs:
            count += 1
            print("    +NOK #" + str(count))
            print("        -" + str("firstLink") + " = " + str(NOK["firstLink"]))
            print("        -" + str("secondLink") + " = " + str(NOK["secondLink"]))
            print("        -" + str("checksum1") + " = " + str(NOK["checksum1"]))
            print("        -" + str("checksum2") + " = " + str(NOK["checksum2"]))
            print("        -" + str("checksum3") + " = " + str(NOK["checksum3"]))
        print()


# tests that each ticket returns the sanem number of
def TESTSummaryWithNOKs():
    for testTicket in listOfTicketsToTest:
        listOfNOKs = getTicketContentNOKs(testTicket)
        summary = getTicketContentSummary(testTicket)
        if len(listOfNOKs) != summary['Problems']:
            print('Lengths do not match')
        if summary['Problems'] != len(listOfNOKs):
            print('NON MATCH UP: ' + str(testTicket))
        else:
            print('match up: ' + str(testTicket))


# tests that all tickets have 5 attachments
def TESTattachments(dontPrint=False):
    for testTicket in listOfTicketsToTest:
        attachments = getTicketAttachments(testTicket)
        print("Ticket " + str(testTicket) + " has " + str(len(attachments)) +
              " attachment(s)")
        if not dontPrint:
            for attachment in attachments:
                print(" -" + str(attachment))
        print()


# runs all tests
def TESTAll():
    TESTproperties()
    TESTattachments()
    TESTSummary()
    TESTNOKs()
    TESTSummaryWithNOKs()


# ignore this test... probably not used anymore
def TESTNOKsInAttachment():
    ticketId = 157108
    attachments = getTicketAttachments(ticketId)
    count = 0
    for attach in attachments:
        url = firstUrlPart + 'ticket/{}/attachments/{}/content'
        response = requests.get(url.format(ticketId, attach), verify=False,
                                cookies=cookie)
        NOKs = re.findall(r'(?<=\n)NOK: .*(?=\n)', response.text)

        if len(NOKs) > 1:
            print(attach)
            count += 1
    print(str(count) + " contained NOK. " + str(len(attachments)) +
          " was the total number of attachments")


# Goes through all tickets in list of tickets to check and compares the
# checksums. This was used to see if there was an overriding pattern (there
# wasn't!)
def TESTChecksumEquality():
    result = [0, 0, 0, 0]  # [1 and 2, 2 and 3, 1 and 3, none] are same
    count = 0
    for testTicket in listOfTicketsToTest:
        listOfNOKs = getTicketContentNOKs(testTicket)
        print("Doing ticket " + str(testTicket))
        for NOK in listOfNOKs:
            if NOK['checksum1'] == NOK['checksum2']:
                result[0] += 1
            if NOK['checksum1'] == NOK['checksum3']:
                result[1] += 1
            if NOK['checksum2'] == NOK['checksum3']:
                result[2] += 1
            else:
                result[3] += 1
            count += 1
    print(result, count)
