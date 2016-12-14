"""
Flask-Stormpath
---------------

The simplest and most secure way to handle user authentication and
authorization with Flask, via Stormpath (https://stormpath.com).

Flask-Stormpath on GitHub: https://github.com/stormpath/stormpath-flask
Documentation on RTFD: http://flask-stormpath.readthedocs.org/en/latest/
"""


from multiprocessing import cpu_count
from subprocess import call

from setuptools import Command, setup


class RunTests(Command):
    """Run our unit / integration tests."""
    description = 'run tests'
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        """Run our tests!"""
        errno = call(['py.test', '-n', str(cpu_count()), 'tests/'])
        raise SystemExit(errno)


setup(
    name = 'Flask-Stormpath',
    version = '0.4.8',
    url = 'https://github.com/stormpath/stormpath-flask',
    license = 'Apache',
    author = 'Stormpath, Inc.',
    author_email = 'python@stormpath.com',
    description = 'Simple and secure user authentication for Flask via Stormpath.',
    long_description = __doc__,
    packages = ['flask_stormpath'],
    cmdclass = {'test': RunTests},
    zip_safe = False,
    include_package_data = True,
    platforms = 'any',
    install_requires = [
        'Flask>=0.11.1',
        'Flask-Login==0.4.0',
        'Flask-WTF>=0.13.1',
        'facebook-sdk==2.0.0',
        'oauth2client==4.0.0',
        'stormpath==2.4.5',
        'blinker==1.4'
    ],
    extras_require = {
        'test': ['coverage', 'pytest', 'pytest-cov', 'pytest-env', 'python-coveralls', 'Sphinx', 'pytest-xdist'],
    },
    dependency_links=[
        'git+git://github.com/pythonforfacebook/facebook-sdk.git@e65d06158' +
        'e48388b3932563f1483ca77065951b3#egg=facebook-sdk-1.0.0-alpha',
    ],
    classifiers=[
        'Environment :: Web Environment',
        'Framework :: Flask',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Internet :: WWW/HTTP :: Session',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
)
