# -*- coding: utf-8 -*-

"""
Python API for manipulating files on box.com(a.k.a box.net).
"""

__author__ = "Hui Zheng"
__copyright__ = "Copyright 2011-2012 Hui Zheng"
__credits__ = ["Hui Zheng"]
__license__ = "MIT <http://www.opensource.org/licenses/mit-license.php>"
__version__ = "0.1"
__email__ = "xyzdll[AT]gmail[DOT]com"

import ConfigParser
import errno
import json
import os
import re
from datetime import datetime
import socket
import urllib
import urllib2

from poster.encode import multipart_encode
from poster.streaminghttp import register_openers
from mechanize._mechanize import FormNotFoundError

from pybox.utils import encode, get_browser, get_logger, get_sha1, is_posix, \
        stringify, retry


logger = get_logger()


class ClientError(Exception):
    """Client-side error"""
    pass


class ConfigError(ClientError):
    """Configuration error"""
    pass


class ParameterError(ClientError):
    """Parameter error"""
    pass


class StatusError(Exception):
    """Status error"""
    pass


class RequestError(Exception):
    """request error"""
    pass


class ForbiddenError(Exception):
    """forbidden error"""
    pass


class FileError(Exception):
    """File error"""
    pass


class FileNotFoundError(FileError):
    """File not found error"""
    pass


class FileConflictionError(FileError):
    """File confliction error"""
    pass


class MethodNotALLowedError(FileError):
    """Method not allowed error"""
    pass


class DiffResult(object):
    """Wrap diff results"""

    class _DiffResultItem(object):
        """Diff result for a context directory"""

        def __init__(self, container, context_node, ignore_common=True):
            self.container = container
            self.context_node = context_node
            self._client_uniques = ([], [])
            self._server_uniques = ([], [])
            self._compares = ([], [])
            self._ignore_common = ignore_common

        def get_client_unique(self, is_file):
            return self._client_uniques[0 if is_file else 1]

        def add_client_unique(self, is_file, path):
            self.get_client_unique(is_file).append(
                    path[self.container.local_prelen:])

        def get_server_unique(self, is_file):
            return self._server_uniques[0 if is_file else 1]

        def add_server_unique(self, is_file, mapping):
            uniques = self.get_server_unique(is_file)
            for name, node in mapping.iteritems():
                context = "/".join(self.container.context)
                path = (context + "/" + name)[self.container.remote_prelen:]
                uniques.append((path, node))

        def get_compare(self, is_diff):
            return self._compares[0 if is_diff else 1]

        def add_compare(self, is_diff, localpath, remotenode):
            if is_diff or not self._ignore_common:
                self.get_compare(is_diff).append(
                        (localpath[self.container.local_prelen:], remotenode))

    def __init__(self, localdir, remotedir, ignore_common=True):
        self.localdir = localdir
        self.local_prelen = len(localdir) + 1
        self.remotedir = remotedir
        self.remotename = remotedir['name']
        self.remote_prelen = len(self.remotename) + 1
        self.items = []
        self.context = []
        self._ignore_common = ignore_common

    def start_add(self, context_node):
        item = DiffResult._DiffResultItem(
                self, context_node, self._ignore_common)
        self.context.append(context_node['name'])
        self.items.append(item)
        return item

    def end_add(self):
        self.context.pop()

    def get_client_unique(self, is_file):
        for item in self.items:
            for path in item.get_client_unique(is_file):
                yield (path, item.context_node)

    def get_server_unique(self, is_file):
        for item in self.items:
            #yield iter(item.get_server_unique(is_file)).next()
            for i in item.get_server_unique(is_file):
                yield i

    def get_compare(self, is_file):
        for item in self.items:
            for localpath, remotenode in item.get_compare(is_file):
                yield (localpath, remotenode, item.context_node)

    def report(self):
        result = ([], [], [], [], [], [])
        for item in self.items:
            result[0].extend(item.get_client_unique(True))
            result[1].extend(item.get_client_unique(False))
            result[2].extend([l for l, _ in item.get_server_unique(True)])
            result[3].extend([l for l, _ in item.get_server_unique(False)])
            result[4].extend([l for l, _ in item.get_compare(True)])
            if not self._ignore_common:
                result[5].extend([l for l, _ in item.get_compare(False)])
        return result

    def __unicode__(self):
        result = self.report()
        return u"diff between client path({}) and server path({}):\n" \
                "[client only files]:\n{}\n"  \
                "[client only folders]:\n{}\n" \
                "[server only files]:\n{}\n" \
                "[server only folders]:\n{}\n" \
                "[diff files]:\n{}\n" \
                "[common files]:\n{}\n".format(
                        self.localdir, self.remotename,
                        ", ".join(result[0]),
                        ", ".join(result[1]),
                        ", ".join(result[2]),
                        ", ".join(result[3]),
                        ", ".join(result[4]),
                        "***ignored***" if self._ignore_common
                        else ", ".join(result[5]),
                        )

    def __str__(self):
        return encode(unicode(self))


def forgive_request(e):
    """Give the failed request a retry"""
    if isinstance(e, urllib2.HTTPError):
        err = e.code
        if err >= 500: # not client's fault, try our luck
            return True
        elif err == 401: # unauthorized, try to update tokens
            return BoxApi.update_auth_token
        elif err == 408: # time-out
            return True
        elif err == 429: # too many requests
            return True
        elif err == 403: # forbidden
            return ForbiddenError()
        elif err == 404: # not found
            return FileNotFoundError()
        elif err == 409: # file confliction
            return FileConflictionError()
        elif err == 405: # method not allowd
            return MethodNotALLowedError()
        elif err == 400: # bad request
            return RequestError()
    elif isinstance(e, urllib2.URLError):
        #if isinstance(e.reason, socket.timeout):
            #return True
        if isinstance(e.reason, socket.error):
            return True
        else:
            logger.error("non socket.error: {}".format(e))
    elif isinstance(e, socket.error):
        return True


class BoxApi(object):
    """Box API"""
    BOX_URL = "box.com/2.0/"
    BOX_API_URL = "api." + BOX_URL
    BASE_URL = "https://" + BOX_API_URL
    OAUTH_URL = "https://www.box.com/api/oauth2/"
    TOKEN_URL = OAUTH_URL + "token"
    AUTH_URL = OAUTH_URL + "authorize"
    UPLOAD_URL = "https://upload.box.com/api/2.0/files{}/content"
    DOWNLOAD_URL = BASE_URL + "files/{}/content"
    ROOT_ID = "0"
    TIME_FORMAT = "%Y-%m-%d %H:%M"
    MAX_TOKEN_DAYS = 60
    SAFE_TOKEN_DAYS = 10
    LIST_SIZE = 1000 # max number that box supports(its default is 100)

    # patterns
    FILENAME_PATTERN = re.compile('(.*filename=")(.+)(".*)')

    def __init__(self):
        conf_file = os.path.expanduser(
                "~/.boxrc" if is_posix() else "~/_boxrc")
        if not os.path.exists(conf_file):
            raise ConfigError(
                    "Configuration file {} not found".format(conf_file))

        try:
            conf_parser = ConfigParser.ConfigParser()
            conf_parser.read(conf_file)
            self._conf_file = conf_file
            self._conf_parser = conf_parser
            self._client_id = conf_parser.get("app", "client_id")
            self._client_secret = conf_parser.get("app", "client_secret")
        except ConfigParser.NoSectionError as e:
            raise ConfigError("{} (in configuration file {})"
                    .format(e, conf_file))

        self._access_token = None
        self._refresh_token = None
        self._token_time = None
        self._account = None

    @staticmethod
    def _log_response(response):
        """Log response"""
        logger.debug("response: {}".format(stringify(response)))

    @staticmethod
    def _parse_response(response):
        code = response.getcode()
        if code == 204:
            logger.info("no content")
            return None

        rsp_str = response.read()
        try:
            response_obj = json.loads(rsp_str)
        except:
            raise StatusError("non-json response: {}".format(rsp_str))

        if 'error' in response_obj:
            raise StatusError("{}({})".format(
                response_obj['error'],
                response_obj['error_description']))
        return response_obj

    @retry(urllib2.URLError, forgive_request, tries=10, logger=logger)
    def _retryable_auth_request(self, url, data, headers, method):
        return self._auth_request(url, data, headers, method)

    def _auth_request(self, url, data, headers, method):
        logger.debug(u"requesting {}...".format(url))
        req = urllib2.Request(url, data, headers)
        if method:
            req.get_method = lambda: method
        req.add_header('Authorization', "Bearer {}".format(self._access_token))
        return urllib2.urlopen(req, timeout=60)

    def _request(self, url, data=None, headers=None,
            method=None, is_json=True, retryable=True):
        auth_req = ('_retryable' if retryable else '') + '_auth_request'
        response = getattr(self, auth_req)(url, data, headers or {}, method)
        if response:
            if is_json:
                info = self._parse_response(response)
                self._log_response(info)
                return info
            else:
                return response

    def _check(self):
        assert self._access_token, "access token no found"

    @classmethod
    def _get_filename(cls, response):
        disposition = response['content-disposition']
        logger.debug("disposition: {}".format(disposition))
        return cls.FILENAME_PATTERN.search(disposition).groups()[1]

    @classmethod
    def _automate(cls, url, login, password):
        browser = get_browser(True)
        browser.open(url) # suppress output?

        browser.select_form(name='login_form')
        browser['login'] = login
        browser['password'] = password

        browser.submit()
        if not browser.viewing_html():
            raise StatusError("something is wrong when browsing HTML")

        browser.select_form(name='consent_form')

        response = browser.submit()
        if not browser.viewing_html():
            raise StatusError("something is wrong when browsing HTML")

        url = response.geturl()
        import urlparse
        parsed = urlparse.parse_qs(urlparse.urlparse(url).query)
        return parsed['code'][0], parsed['state'][0]

    def _authorize(self, login, password):
        """Automates authorization process.

        Refer: http://developers.box.com/oauth/
        """
        assert login, "Login must be provided"
        assert password, "Password must be provided"

        import binascii
        security_token = 'security_token' + binascii.hexlify(os.urandom(20))
        params = urllib.urlencode({
                   'response_type': "code",
                   'client_id': self._client_id,
                   'redirect_uri': "http://localhost",
                   'state': security_token})
        url = self.AUTH_URL + "?" + params
        logger.debug("browsing auth url: {}".format(url))
        try:
            code, state = self._automate(url, login, password)
            if state != security_token:
                raise StatusError("security token mismatched(CSRF)")

            logger.info("authorization succeeded")
            return code
        except FormNotFoundError as e:
            logger.error(e.message)
            raise ParameterError(
                    "authorization failed, please check your login/password")

    def get_auth_token(self, account, login, password=None):
        """Get the access token and refresh token.
        This method MUST be called before any account-relative action.

        If auth token has not been set before, read from configuration file.
        If not found, initiate authorization.
        Refer: http://developers.box.com/oauth/
        """
        if not login and self._access_token:
            logger.info("reuse the saved access token")
            return self._access_token, self._refresh_token, self._token_time

        parser = self._conf_parser
        self._account = account = "account-" + account
        access_token = refresh_token = token_time = None
        if not parser.has_section(account):
            logger.info("adding account section {}".format(account))
            parser.add_section(account)
        elif not login:
            try:
                self._refresh_token = refresh_token \
                        = parser.get(account, "refresh_token")
                self._access_token = access_token \
                        = parser.get(account, "access_token")
                self._token_time = token_time \
                        = datetime.strptime(parser.get(
                            account, "token_time"), self.TIME_FORMAT)
                days = (datetime.now() - token_time).days
                if days > self.MAX_TOKEN_DAYS:
                    raise ConfigError("refresh token has expired" \
                            "({} days old), please relogin".format(days))
                elif days > self.SAFE_TOKEN_DAYS:
                    logger.warn("refresh token is {} days old".format(days))

                if refresh_token and access_token:
                    return access_token, refresh_token, token_time
            except ConfigError:
                raise
            except Exception as e:
                logger.warn(e.message)

        if login:
            authorization_code = self._authorize(login, password)
            return self._fetch_token(authorization_code)

        if refresh_token:
            return self._fetch_token()

        raise ConfigError("refresh token must be provided for {},"\
                "please change configuration or relogin".format(account))

    def _fetch_token(self, code=None):
        params = {
                   'client_id': self._client_id,
                   'client_secret': self._client_secret}
        if code:
            params['grant_type'] = 'authorization_code'
            params['code'] = code
        else:
            params['grant_type'] = 'refresh_token'
            params['refresh_token'] = self._refresh_token
        params = urllib.urlencode(params)
        logger.debug("get_token params: {}".format(params))
        response = urllib.urlopen(self.TOKEN_URL, params)
        rsp_obj = self._parse_response(response)
        self._access_token = rsp_obj['access_token']
        self._refresh_token = rsp_obj['refresh_token']
        self._conf_parser.set(
                self._account, "access_token", self._access_token)
        self._conf_parser.set(
                self._account, "refresh_token", self._refresh_token)
        now = datetime.now()
        self._conf_parser.set(self._account, "token_time",
                datetime.strftime(now, self.TIME_FORMAT))
        with open(self._conf_file, 'w') as conf:
            self._conf_parser.write(conf)
        logger.info("tokens fetched")
        return self._access_token, self._refresh_token, now

    def update_auth_token(self):
        """Update access token"""
        logger.info("updating tokens")
        return self._fetch_token()

    def get_account_info(self):
        """Get account information

        Refer:
        http://developers.box.com/docs/#users-get-the-current-users-information
        """
        self._check()

        return self._request(self.BASE_URL + "users/me")

    def list(self, folder_id=None, extra_params=None, by_name=False):
        """List files under the given folder.

        Refer: http://developers.box.com/docs/#folders-retrieve-a-folders-items
        """
        ### TODO: if list item count > 1000, auto-paginate when necessary
        self._check()

        if not folder_id:
            folder_id = self.ROOT_ID
        elif by_name:
            folder_id = self._convert_to_id(folder_id, False)
        extra_params = extra_params or {}
        limit = extra_params.get('limit', self.LIST_SIZE)
        offset = extra_params.get('offset', 0)
        fields = extra_params.get('fields', '')
        #fields = extra_params.get('fields', 'created_at,modified_at')
        try:
            limit = int(limit)
            offset = int(offset)
        except ValueError as e:
            logger.error(e.message)
            raise ParameterError("both limit and offset should be integers")

        params = urllib.urlencode({
            'limit': limit, 'offset': offset, 'fields': fields})
        url = "{}folders/{}/items?{}".format(
                self.BASE_URL, encode(folder_id), params)
        return self._request(url)

    @staticmethod
    def _get_file_id(files, name, is_file):
        if is_file:
            type_ = "file"
        else:
            type_ = "folder"
        logger.debug(u"checking {} {}".format(type_, name))
        files = files['entries'] or []
        for f in files:
            if f['name'] == name and f['type'] == type_:
                f_id = f['id']
                logger.debug(u"found name '{}' with id {}".format(name, f_id))
                return f_id

    def get_file_id(self, path, is_file=None):
        """Return the file's id for the given server path.
        If is_file is True, check only file type,
        if is_file is False, check only folder type,
        if is_file is None, check both file and folder type.
        Return id and type(whether file or not).
        """
        if not path or path == "/":
            return self.ROOT_ID, False

        path = os.path.normpath(path)
        paths = [p for p in path.split(os.sep) if p]
        folder_id = self.ROOT_ID
        for name in paths[:-1]:
            logger.debug(u"look up folder '{}' in {}".format(name, folder_id))
            files = self.list(folder_id)
            folder_id = self._get_file_id(files, name, False)
            if not folder_id:
                logger.debug(u"no found {} under folder {}".
                        format(name, folder_id))
                return None, None
        # time to check name
        name = paths[-1]
        logger.debug(u"checking name: {}".format(name))
        files = self.list(folder_id)
        if not is_file:
            id_ = self._get_file_id(files, name, False)
            if id_:
                return id_, False

        if is_file is None or is_file:
            return self._get_file_id(files, name, True), True

        return None, None

    def _convert_to_id(self, name, is_file):
        file_id, is_file = self.get_file_id(name, is_file)
        if not file_id:
            logger.error(u"cannot find id for {}".format(name))
            raise ValueError("wrong file name")
        return file_id

    def get_file_info(self, file_id, by_name=False):
        """Get file's detailed information

        Refer:
        http://developers.box.com/docs/#files-get
        """
        self._check()

        if by_name:
            file_id = self._convert_to_id(file_id, True)
        url = "{}{}s/{}".format(
                self.BASE_URL, "file", encode(file_id))
        try:
            return self._request(url)

        except FileNotFoundError:
            logger.error(u"cannot find a file with id: {}".format(file_id))
            raise
        except MethodNotALLowedError:
            if not file_id.isdigit():
                raise ParameterError("id({}) is ill-formed".format(file_id))
            raise

    def get_folder_info(self, folder_id, by_name=False):
        """Get folder's detailed information.
        Result is array type due to pagination

        Refer:
        http://developers.box.com/docs/#folders-get-information-about-a-folder
        """
        self._check()

        if by_name:
            folder_id = self._convert_to_id(folder_id, False)
        try:
            results = []
            limit = self.LIST_SIZE
            offset = 0
            while True:
                params = urllib.urlencode(
                        {'limit': limit, 'offset': offset})
                url = "{}{}s/{}?{}".format(
                        self.BASE_URL, 'folder', encode(folder_id), params)
                result = self._request(url)
                results.append(result)
                children = result['item_collection']
                count = children['total_count']
                offset = children['offset']
                limit = children['limit']
                offset += limit
                if offset >= count:
                    break
            return results
        except FileNotFoundError:
            logger.error(u"cannot find a folder with id: {}".format(folder_id))
            raise
        except MethodNotALLowedError:
            if not folder_id.isdigit():
                raise ParameterError("id({}) is ill-formed".format(folder_id))
            raise

    def mkdir(self, name, parent=None, by_name=False):
        """Create a directory if it does not exists.
        Raise `FileConflictionError` if it already exists.

        Refer: http://developers.box.com/docs/#folders-create-a-new-folder
        """
        self._check()

        if not parent:
            parent = self.ROOT_ID
        elif by_name:
            parent = self._convert_to_id(parent, False)

        url = "{}folders".format(self.BASE_URL)
        data = {"parent": {"id": encode(parent)},
                "name": encode(name)}
        try:
            return self._request(url, json.dumps(data))
        except FileConflictionError as e:
            logger.warn(u"directory {} already exists".format(name))
            e.args = (encode(name), parent)
            raise

    def mkdirs(self, name, parent=None, by_name=False):
        """Create a directory if it does not exists and return its id.
        No error is raised even it's an already existing directory.
        """
        try:
            return self.mkdir(name, parent, by_name)['id']
        except FileConflictionError as e:
            name, parent = e.args
            return self._get_file_id(self.list(parent), name, False)

    def rmdir(self, id_, recursive=False, by_name=False):
        """Remove the given directory

        Refer: http://developers.box.com/docs/#folders-delete-a-folder
        """
        self._remove(False, id_, by_name, recursive)

    def remove(self, id_, by_name=False):
        """Remove the given file

        Refer: http://developers.box.com/docs/#files-delete-a-file
        """
        self._remove(True, id_, by_name)

    def _remove(self, is_file, id_, by_name, recursive=False):
        self._check()

        if by_name:
            id_ = self._convert_to_id(id_, is_file)
        if is_file:
            type_ = "file"
        else:
            type_ = "folder"
        url = "{}{}s/{}".format(self.BASE_URL, type_, id_)
        if recursive and not is_file:
            url += "?recursive=true"
        try:
            return self._request(url, method='DELETE')
        except FileNotFoundError:
            logger.error(u"cannot find a {} with id: {}".format(
                type_, id_))
            raise
        except RequestError:
            if not recursive and not is_file:
                logger.error(u"Probably the folder to be deleted({}) " \
                        "is nonempty, try recursive deletion".format(id_))
            raise
        except MethodNotALLowedError:
            if not id_.isdigit():
                raise ParameterError("id({}) is ill-formed".format(id_))
            raise

    def rename_file(self, id_, new_name, by_name=False):
        """Rename a file

        Refer:
        http://developers.box.com/docs/#files-update-a-files-information
        """
        self._rename(True, id_, new_name, by_name)

    def rename_dir(self, id_, new_name, by_name=False):
        """Rename a directory

        Refer:
        http://developers.box.com/docs/#folders-update-information-about-a-folder
        """
        self._rename(False, id_, new_name, by_name)

    def _rename(self, is_file, id_, new_name, by_name):
        try:
            return self._update_info(is_file, id_,
                    {"name": encode(new_name)}, by_name)
        except FileConflictionError:
            logger.error(u"{} {} already exists".format(
                "File" if is_file else "Folder", new_name))
            raise

    def _update_info(self, is_file, id_, new_info, by_name):
        """Update a file/directory's information

        Refer:
        http://developers.box.com/docs/#files-update-a-files-information
        http://developers.box.com/docs/#folders-update-information-about-a-folder
        """
        self._check()

        if by_name:
            id_ = self._convert_to_id(id_, is_file)
        if is_file:
            type_ = "file"
        else:
            type_ = "folder"
        url = "{}{}s/{}".format(self.BASE_URL, type_, id_)
        try:
            return self._request(url, json.dumps(new_info), method='PUT')
        except FileNotFoundError:
            logger.error(u"cannot find a {} with id: {}".format(
                type_, id_))
            raise

    def move_file(self, file_, new_folder, by_name=False):
        """Move a file to another folder

        Refer:
        http://developers.box.com/docs/#files-update-a-files-information
        """
        self._move(True, file_, new_folder, by_name)

    def move_dir(self, folder, new_folder, by_name=False):
        """Move a directory to another folder

        Refer:
        http://developers.box.com/docs/#folders-update-information-about-a-folder
        """
        self._move(False, folder, new_folder, by_name)

    def _move(self, is_file, target, new_folder, by_name):
        if by_name:
            new_folder = self._convert_to_id(new_folder, False)
        try:
            return self._update_info(is_file, target,
                    {"parent": {"id": encode(new_folder)}}, by_name)
        except RequestError: # e.g. move to descendent
            logger.error(u"{} {} cannot move to {}".format(
                "File" if is_file else "Folder", target, new_folder))
            raise

    def download_dir(self, folder_id, localdir=None, by_name=False):
        """Download the directory with the given id to a local directory"""
        self._check()

        folder_info = self.get_folder_info(folder_id, by_name)
        folder_name = folder_info[0]['name']
        localdir = os.path.join(localdir or ".", folder_name)
        try:
            os.makedirs(localdir)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise

        files = (entry for entries in
                (i['item_collection']['entries'] for i in folder_info)
                for entry in entries)
        for f in files:
            file_name = f['name']
            file_id = f['id']
            file_type = f['type']
            if file_type == 'file':
                localfile = os.path.join(localdir, file_name)
                if os.path.exists(localfile):
                    # check
                    sha1 = f['sha1']
                    if get_sha1(localfile) == sha1:
                        logger.debug("same sha1")
                        continue
                # download
                self.download_file(file_id, localdir)
            elif file_type == 'folder':
                self.download_dir(file_id, localdir)
            else:
                logger.warn(u"unexpected file type".format(file_type))

    def download_file(self, file_id, localdir=None, by_name=False):
        """Download the file with the given id to a local directory

        Refer:
        http://developers.box.com/docs/#files-download-a-file
        """
        self._check()

        if by_name:
            file_id = self._convert_to_id(file_id, True)
        localdir = encode(localdir or ".")
        url = self.DOWNLOAD_URL.format(encode(file_id))
        self._do_download(localdir, url)

    @retry((urllib2.URLError, socket.error), forgive_request,
            tries=10, logger=logger)
    def _do_download(self, localdir, url):
        logger.debug("download url: {}".format(url))
        stream = self._request(url, is_json=False, retryable=False)
        meta = stream.info()
        name = self._get_filename(meta)
        size = int(meta.getheaders("Content-Length")[0])
        logger.debug("filename: {} with size: {}".format(name, size))
        BLOCK_SIZE = 65536
        with open(os.path.join(localdir, name), 'wb') as f:
            while True:
                buf = stream.read(BLOCK_SIZE)
                if not buf:
                    break
                f.write(buf)

    def upload(self, uploaded, parent=None, by_name=False, precheck=True):
        """Upload the given file/directory to a remote directory.
        In case a file already exists on the server, upload will be skipped
        if two files have the same SHA1, otherwise a new version of the file
        will be uploaded.

        Refer:
        http://developers.box.com/docs/#files-upload-a-file
        http://developers.box.com/docs/#files-upload-a-new-version-of-a-file
        """
        self._check()

        if not parent:
            parent = self.ROOT_ID
        elif by_name:
            parent = self._convert_to_id(parent, False)
        uploaded = os.path.normpath(uploaded)
        if os.path.isfile(uploaded):
            self._upload_file(uploaded, parent, precheck)
        elif os.path.isdir(uploaded):
            self._upload_dir(uploaded, parent, precheck)
        else:
            logger.debug("ignore to upload {}".format(uploaded))

    def _upload_dir(self, upload_dir, parent, precheck):
        upload_dir_id = self.mkdirs(os.path.basename(upload_dir), parent)
        assert upload_dir_id, "upload_dir_id should be present"
        for filename in os.listdir(upload_dir):
            path = os.path.join(upload_dir, filename)
            self.upload(path, upload_dir_id, False, precheck)

    def _check_file_on_server(self, filepath, parent):
        """Check if the file already exists on the server
        Return `None` if not,
        return `True` if it does, and has the same SHA,
        return id if it does, but has the different SHA.
        """
        filename = os.path.basename(filepath)
        files = self.list(parent)['entries'] or []
        for f in files:
            name = f['name']
            if name == filename:
                logger.debug(u"found same filename: {}".format(name))
                if f['type'] == 'folder':
                    logger.error(u"A folder named '{}' already exists on" \
                            " the server".format(name))
                    raise FileConflictionError()
                sha1 = f['sha1']
                if get_sha1(filepath) == sha1:
                    logger.debug("same sha1")
                    return True
                else:
                    logger.debug("diff sha1")
                    return f['id']
        logger.debug(u"file {} not found under the directory {}"
                .format(filename, parent))

    def _upload_file(self, upload_file, parent, precheck):
        remote_id = None
        if precheck is True:
            remote_id = self._check_file_on_server(upload_file, parent)
            if remote_id is True:
                logger.debug(u"skip uploading file: {}".format(upload_file))
                return
        elif precheck:
            remote_id = precheck

        url = self.UPLOAD_URL.format(("/" + remote_id) if remote_id else "")
        return self._do_upload(upload_file, parent, url)

    @retry(urllib2.URLError, forgive_request, tries=10, logger=logger)
    def _do_upload(self, upload_file, parent, url):
        logger.debug(u"uploading {} to {}".format(upload_file, parent))

        # Register the streaming http handlers with urllib2
        register_openers()
        upload_file = encode(upload_file)
        # add "If-Match: ETAG_OF_ORIGINAL" for file's new version?
        datagen, headers = multipart_encode({
            'filename': open(upload_file), 'parent_id': parent})

        class DataWrapper(object):
            """Fix filename encoding problem"""

            def __init__(self, filename, datagen, headers):
                header_data = []
                while True:
                    data = datagen.next()

                    if BoxApi.FILENAME_PATTERN.search(data):
                        length = int(headers['Content-Length']) - len(data)
                        filename = os.path.basename(filename)
                        data = BoxApi.FILENAME_PATTERN.sub(
                                "\g<1>" + filename + "\\3", data)
                        headers['Content-Length'] = str(length + len(data))
                        header_data.insert(0, data)
                        break
                    else:
                        header_data.insert(0, data)

                self.datagen = datagen
                self.header_data = header_data

            def __iter__(self):
                return self

            def next(self):
                if self.header_data:
                    return self.header_data.pop()
                else:
                    return self.datagen.next()

        datagen = DataWrapper(upload_file, datagen, headers)
        return self._request(url, datagen, headers, retryable=False)

    def compare_file(self, localfile, remotefile, by_name=False):
        """Compare files between server and client(as per SHA1)"""
        sha1 = get_sha1(localfile)
        info = self.get_file_info(remotefile, by_name)
        return sha1 == info['sha1']

    def compare_dir(self, localdir, remotedir,
            by_name=False, ignore_common=True):
        """Compare directories between server and client"""
        remotedir = self.get_folder_info(remotedir, by_name)
        localdir = os.path.normpath(localdir)
        return self._compare_dir(localdir, remotedir,
                DiffResult(localdir, remotedir[0], ignore_common))

    def _compare_dir(self, localdir, remotedir, result):
        children = [entry for entries in
                (i['item_collection']['entries'] for i in remotedir)
                for entry in entries]
        server_file_map = dict((f['name'], f) \
                            for f in children if 'sha1' in f)
        server_folder_map = dict((f['name'], f) \
                            for f in children if 'sha1' not in f)
        result_item = result.start_add(remotedir[0])

        subfolders = []
        for filename in os.listdir(localdir):
            path = os.path.join(localdir, filename)
            if os.path.isfile(path):
                node = server_file_map.pop(filename, None)
                if node is None:
                    result_item.add_client_unique(True, path)
                else:
                    result_item.add_compare(
                            get_sha1(path) != node['sha1'], path, node)
            elif os.path.isdir(path):
                folder_node = server_folder_map.pop(filename, None)
                if folder_node is None:
                    result_item.add_client_unique(False, path)
                else:
                    subfolders.append(folder_node)
        result_item.add_server_unique(True, server_file_map)
        result_item.add_server_unique(False, server_folder_map)
        # compare recursively
        for folder in subfolders:
            path = os.path.join(localdir, folder['name'])
            folder = self.get_folder_info(folder['id'])
            self._compare_dir(path, folder, result)
        result.end_add()
        return result

    def sync(self, localdir, remotedir, dry_run=False, by_name=False,
            ignore=None):
        """Sync directories between client(source) and server(destination)"""
        if dry_run:
            logger.info("dry run...")
        result = self.compare_dir(localdir, remotedir, by_name)
        client_unique_files = result.get_client_unique(True)
        for path, node in client_unique_files:
            f = os.path.join(localdir, path)
            id_ = node['id']
            if ignore and ignore(f):
                logger.info(u"ignoring file: {}".format(f))
            else:
                logger.info(u"uploading file: {} to node {}".format(f, id_))
                if not dry_run:
                    self.upload(f, id_, False, False)
        client_unique_folders = result.get_client_unique(False)
        for path, node in client_unique_folders:
            f = os.path.join(localdir, path)
            id_ = node['id']
            logger.info(u"uploading folder: {} to node {}".format(f, id_))
            if not dry_run:
                self.upload(f, id_, False, False)

        server_unique_files = result.get_server_unique(True)
        for path, node in server_unique_files:
            id_ = node['id']
            logger.info(u"removing file {} with id = {}".format(path, id_))
            if not dry_run:
                self.remove(id_)
        server_unique_folders = result.get_server_unique(False)
        for path, node in server_unique_folders:
            id_ = node['id']
            logger.info(u"removing folder {} with id = {}".format(path, id_))
            if not dry_run:
                self.rmdir(id_, True)

        diff_files = result.get_compare(True)
        for localpath, remote_node, context_node in diff_files:
            localfile = os.path.join(localdir, localpath)
            remote_id = remote_node['id']
            remotedir_id = context_node['id']
            logger.info(u"uploading diff file {} with remote id = {} under {}"
                    .format(localfile, remote_id, remotedir_id))
            if not dry_run:
                self.upload(localfile, remotedir_id, False, remote_id)

        #diff_files = result.get_compare(False)
        #for localpath, remote_node, context_node in diff_files:
            #localfile = os.path.join(localdir, localpath)
            #remote_id = remote_node['id']
            #remotedir_id = context_node['id']
            #print u"same file {} with remote id = {} under {}".format(
                    #localfile, remote_id, remotedir_id)
