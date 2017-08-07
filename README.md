# AutoChecksum
Automate the investigation of CASTOR checksum tickets on RT. 

## Requirements

There is only one requirement: the python `requests` module.

Install this with `pip3 install requests`.

## Usage

Run `python3 autoChecksum.py` to process the tickets manually. This creates logs under `log/`.

## Use Python3

If considering trying to run on python2.x, there were breaking changes
including 'print' is now a function between 2.x and 3.x so be cautious.
The python website states that all versions of python3.x are backward
compatible. I have tested this on python 3.4 and 3.5.



## Other files required:
NOTE: the below shell scripts probably require execute permissions

Name                  | Type
--------------------- | ---
./sshCat.sh           | file
./sshLs.sh            | file
./sshRalreplicas.sh   | file
./log/                | folder
./secret.py           | file    

## Changes

new version 29.11.2016
- added check that ssh-agent is running this means that the script will no longer run if ssh-agent isn't running.

new version 12.12.2016 
- changed ssh scripts to include `-o "StrictHostKeyChecking no"` this means that
  'are you sure that you want to connect (yes/no)' will not pop

new version 31.01.2017 
- saw the boundary case for the first time so added some comments to make it clear why we logged the boundary case

new version 21.04.2017
- Error handle to ticket, sets ticket priority to 100 also checks that python version is 3.

new version 28.06.2017
- Add EXPECTED_NUM_ATTACHMENTS global rather than hard coding to '5'

new version 07.07.2017
- Create the 'log/' dir if necessary
- Check that scripts are executable rather than attempting to run and
  raising an error to the ticket.
- Add a production USER_NAME and USER_PASSWORD
- Force ssh as root.


## How it works

The functions should be self explainatory. Lots of them are to do with
getting/changing stuff from RT which is not longer needed but may be useful
functionality in the future so I kept them. Each time the script is run,
the function 'run()' is called which acts as a wrapper to all other calls so
that exceptions are definitely caught and sent to the log file rather than to
standard out.

There are a number of LIMITATIONS highlighted in comments. Mainly, it
cannot deal with merged tickets because it may end up with a situation where
it investigates one ticket and deletes a file from a different merged ticket.
