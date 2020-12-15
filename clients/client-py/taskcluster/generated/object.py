# coding=utf-8
#####################################################
# THIS FILE IS AUTOMATICALLY GENERATED. DO NOT EDIT #
#####################################################
# noqa: E128,E201
from ..client import BaseClient
from ..client import createApiClient
from ..client import config
from ..client import createTemporaryCredentials
from ..client import createSession
_defaultConfig = config


class Object(BaseClient):
    """
    The object service provides HTTP-accessible storage for large blobs of data.
    """

    classOptions = {
    }
    serviceName = 'object'
    apiVersion = 'v1'

    def ping(self, *args, **kwargs):
        """
        Ping Server

        Respond without doing anything.
        This endpoint is used to check that the service is up.

        This method is ``stable``
        """

        return self._makeApiCall(self.funcinfo["ping"], *args, **kwargs)

    def uploadObject(self, *args, **kwargs):
        """
        Upload backend data (temporary)

        Upload backend data.

        This method is ``experimental``
        """

        return self._makeApiCall(self.funcinfo["uploadObject"], *args, **kwargs)

    def fetchObjectMetadata(self, *args, **kwargs):
        """
        Download object data

        Get information on how to download an object.  Call this endpoint with a list of acceptable
        download methods, and the server will select a method and return the corresponding payload.
        Returns a 406 error if none of the given download methods are available.

        See [Download Methods](https://docs.taskcluster.net/docs/reference/platform/object/download-methods) for more detail.

        This method is ``experimental``
        """

        return self._makeApiCall(self.funcinfo["fetchObjectMetadata"], *args, **kwargs)

    def download(self, *args, **kwargs):
        """
        Get an object's data

        Get the data in an object directly.  This method does not return a JSON body, but
        redirects to a location that will serve the object content directly.

        URLs for this endpoint, perhaps with attached authentication (`?bewit=..`),
        are typically used for downloads of objects by simple HTTP clients such as
        web browsers, curl, or wget.

        This method is limited by the common capabilities of HTTP, so it may not be
        the most efficient, resilient, or featureful way to retrieve an artifact.
        Situations where such functionality is required should ues the
        `fetchObjectMetadata` API endpoint.

        See [Simple Downloads](https://docs.taskcluster.net/docs/reference/platform/object/simple-downloads) for more detail.

        This method is ``experimental``
        """

        return self._makeApiCall(self.funcinfo["download"], *args, **kwargs)

    funcinfo = {
        "download": {
            'args': ['name'],
            'method': 'get',
            'name': 'download',
            'route': '/download/<name>',
            'stability': 'experimental',
        },
        "fetchObjectMetadata": {
            'args': ['name'],
            'input': 'v1/download-object-request.json#',
            'method': 'put',
            'name': 'fetchObjectMetadata',
            'output': 'v1/download-object-response.json#',
            'route': '/download-object/<name>',
            'stability': 'experimental',
        },
        "ping": {
            'args': [],
            'method': 'get',
            'name': 'ping',
            'route': '/ping',
            'stability': 'stable',
        },
        "uploadObject": {
            'args': ['name'],
            'input': 'v1/upload-object-request.json#',
            'method': 'put',
            'name': 'uploadObject',
            'route': '/upload/<name>',
            'stability': 'experimental',
        },
    }


__all__ = ['createTemporaryCredentials', 'config', '_defaultConfig', 'createApiClient', 'createSession', 'Object']
