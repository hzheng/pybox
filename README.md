pybox
=====

INTRODUCTION
------------

`pybox` is a Python API/client that manipulates files on box.com
(a.k.a box.net). It can display user's account information, file structure,
and file information, manage(move/rename/delete/upload/download) files and
directories, and **most importantly**, it can recursively compare and synchronize
directories between client and server.

USAGE
-----

Please take the following steps:

1. Obtain client\_id and client\_secret from [here](https://app.box.com/developers/services).

2. Copy boxrc.example to user's home directory, rename it to .boxrc in a POSIX system
(e.g. Unix, Linux, Mac OS X) or \_boxrc in a non-POSIX system(e.g. Windows).

3. Edit .boxrc/\_boxrc: fill out client\_id and client\_secret with the values
   you've just got in step 1.

4. Copy box-logging.conf.example to box-logging.conf.

5. Edit(optionally) box-logging.conf, e.g. change 'BOX.LOG' to different name
   or path. If you'd like to put this log configuration file to a different 
   directory, don't forget to add an environment variable named LOG\_CONF\_DIR.
 
6. Open a command terminal, change directory to the pybox directory, then run:

    python pybox/boxclient.py -L YOUR\_LOGIN\_EMAIL

    Replace the above email with your actual login email on box.com,
    and type your password when prompted. If login/password combination is
    correct, you will get a success message. At this time, your .boxrc/\_boxrc
    should be updated with valid tokens(i.e. access token and refresh token).
 

7. If you have multiple box accounts, just repeat step 6.

If everything goes smoothly, you are now free to manipulate your files on the
box account(s) without typing password any more. (Well, the true story is:
access token will expire in 1 hour, and refresh token will expire in 60 days.
When the former token expires, the program will automatically use the latter
one to get a new access token and refresh token. That means you don't have to
type password as long as the program runs at least once in every 2 months)


Generally the command is:

    python pybox/boxclient.py -U YOUR_LOGIN [options] [args]

Please be noticed that this time YOUR\_LOGIN is the string you set in step 7.

All supported options are listed as follows:

* _-L, --login_ login to create/update auth tokens

* _-U, --user_ specify user account

* _-a, --auth-token_ print auth token

* _-I, --account-info_ get box account information

* _-t, --target_ specify target type(f for file&lt;default>, d for directory)

* _-l, --list_ list directory

* _--limit_ limit of list items(default and max: 1000)

* _--offset_ offset of list items(default: 0)

* _-w, --what-id_ get a path(server-side)'s id

* _-i, --info_ get file information

* _-M, --mkdir_ make a directory

* _-R, --remove_ remove a file or directory

* _--recursive_ recursive(in rmdir)

* _-m, --move_ move a file or directory

* _-r, --rename_ rename a file or directory

* _-c, --chdir_ change directory

* _-d, --download_ download file

* _-u, --upload_ upload file

* _-C, --compare_ compare local and remote directories

* _-p, --push_ sync(push) local(source) and remote directories(destination)

* _-P, --pull_ sync(pull) remote(source) and local directories(destination)

* _-n, --dry-run_ show what would have been transferred when sync

* _-f, --from-file_ read arguments from file(arguments separated by line break)

EXAMPLES
--------

Assume all the following operations are performed on Bob's account.

Note: only when a remote path is `0`(root id) or consists exclusively of 5+ digits,
will it be considered as a node id. Otherwise, it's interpreted as path
starting from the remote root. If a remote path happens to be `0` or digits, be
sure to prepend it with '/' to avoid confusion.

* show account information:

        python pybox/boxclient.py -Ubob -I

* list all files under root

        python pybox/boxclient.py -Ubob -l /

* create a directory `dir1` under root:

        python pybox/boxclient.py -Ubob -M dir1

* create a directory `dir2` under `dir1`:

        python pybox/boxclient.py -Ubob -c dir1 -M dir2

* get directory `dir1/dir2`(starting from root)'s id:

        python pybox/boxclient.py -Ubob -w dir1/dir2

* upload file `file1`, `file2` and directory `dir3` to root directory:

        python pybox/boxclient.py -Ubob -u file1 file2 dir3

* upload `file3` to a directory whose id is `1005691453`

        python pybox/boxclient.py -Ubob -c1005691453 -u file3

* upload `file4` to a directory whose path is 'path1/path2'

        python pybox/boxclient.py -Ubob -c path1/path2 -u file4

* remove a file whose id is `1005181453`

        python pybox/boxclient.py -Ubob -R 1005181453

* remove a directory whose path is `path1/path2`(starting from root)

        python pybox/boxclient.py -Ubob -R -td path1/path2

* rename file `file1` to `file1.new`, file `file2` to `file2.new`

        python pybox/boxclient.py -Ubob -r file1 file1.new file2 file2.new

* rename directory `dir1` to `dir2`

        python pybox/boxclient.py -Ubob -r -td dir1 dir2

* move a file with id `1025611460` to a directory with id `225236230`

        python pybox/boxclient.py -Ubob -m 1025611460 225236230

* move directory `dir1` to directory `dir2`, directory `dir3/dir4` to directory
  `dir5/dir6/dir7`

        python pybox/boxclient.py -Ubob -td -m dir1 dir2 dir3/dir4 dir5/dir6/dir7

* download a directory `dir1/dir2`

        python pybox/boxclient.py -Ubob -d dir1/dir2

* compare a local directory `/Users/bob/dir1` with a remote directory `dir2/dir3`

        python pybox/boxclient.py -Ubob -C /Users/bob/dir1 dir2/dir3

* sync(push) a local directory `/Users/bob/dir1`(source) with a remote directory
  `dir2/dir3`(destination)

        python pybox/boxclient.py -Ubob -p /Users/bob/dir1 dir2/dir3

* sync(pull) a remote directory `dir2/dir3`(source) with a local directory
  `/Users/bob/dir1`(destination)

        python pybox/boxclient.py -Ubob -P dir2/dir3 /Users/bob/dir1


REFERENCE
---------

[Box API documentation](http://developers.box.com/docs/#api-basics)


LICENSE
-------

Copyright 2014-2015 Hui Zheng

Released under the [MIT License](http://www.opensource.org/licenses/mit-license.php).

