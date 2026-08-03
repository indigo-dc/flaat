# FLAAT

[![eosc-synergy-logo](https://readthedocs.org/projects/flaat/badge/?version=latest)](https://flaat.readthedocs.io/)
[![CI](https://github.com/indigo-dc/flaat/actions/workflows/ci.yml/badge.svg)](https://github.com/indigo-dc/flaat/actions/workflows/ci.yml)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Use decorators for authorising access to OIDC authenticated REST APIs.
Supports [Flask](https://flask.palletsprojects.com/en/2.0.x/), [FastAPI](https://fastapi.tiangolo.com/) and [AIOHTTP](https://docs.aiohttp.org/en/stable/).

## Installation

FLAAT is available on [PyPI](https://pypi.org/project/flaat/). Install using `pip`:

```bash
pip install flaat
```

You can also install from the git repository:

```bash
git clone https://github.com/indigo-dc/flaat
pip install -e ./flaat
```

## Note
Please note that there may be conflicts with the pip package `jwt`,
because its installation can mask `python-jwt`. In case of this error:
```
    class FlaatPyJWKClient(jwt.PyJWKClient):
                           ^^^^^^^^^^^^^^^
AttributeError: module 'jwt' has no attribute 'PyJWKClient'
```
the `jwt package is in the way, and you need to uninstall it, so
python-jwt can be used.

## Documentation

The documentation is available at [readthedocs](https://flaat.readthedocs.io/en/latest/).

## Development

Instructions on development, testing and releasing versions can be found [here](https://flaat.readthedocs.io/en/latest/flaat/development.html).

## License

FLAAT is provided under the [MIT License](https://opensource.org/licenses/MIT).
