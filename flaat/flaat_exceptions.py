# vim: tw=100 foldmethod=indent
"""Define all potential exceptions that we want to raise"""
# MIT License
# Copyright (c) 2017 - 2019 Karlsruhe Institute of Technology - Steinbuch Centre for Computing
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# pylint
# pylint: disable=invalid-name, superfluous-parens, line-too-long

import logging

available_web_frameworks = ["flask", "aiohttp", "fastapi"]
try:
    from werkzeug.exceptions import HTTPException
except ModuleNotFoundError:
    available_web_frameworks.remove("flask")
try:
    from aiohttp import web_exceptions
except ModuleNotFoundError:
    available_web_frameworks.remove("aiohttp")
try:
    from fastapi import HTTPException as FastAPI_HTTPException
except ModuleNotFoundError:
    available_web_frameworks.remove("fastapi")

logger = logging.getLogger(__name__)

if "flask" in available_web_frameworks:

    class FlaatExceptionFlask(HTTPException):
        """Call the corresponding web framework exception, with a custom reason"""

        def __init__(self, status_code, reason=None, **kwargs):
            self.code = status_code
            if reason:
                self.description = reason
            super().__init__()


if "aiohttp" in available_web_frameworks:

    class FlaatExceptionAio(web_exceptions.HTTPError):
        """Call the corresponding web framework exception, with a custom reason"""

        def __init__(self, status_code, reason=None, **kwargs):
            self.status_code = status_code
            if reason:
                super().__init__(text="%s: %s" % (status_code, reason))
            else:
                super().__init__()


if "fastapi" in available_web_frameworks:

    class FlaatExceptionFastapi(FastAPI_HTTPException):
        """Call the corresponding web framework exception, with a custom reason"""

        def __init__(self, status_code, reason=None, **kwargs):
            self.code = status_code
            if reason:
                self.description = reason
                super().__init__(status_code=status_code, detail=reason)
            else:
                super().__init__(status_code=status_code)
