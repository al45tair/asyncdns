import sys
from setuptools import setup
from setuptools.command.test import test as TestCommand

class PyTest(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        import pytest
        errno = pytest.main(self.test_args)
        sys.exit(errno)

with open('README.rst', 'rb') as f:
    long_desc = f.read().decode('utf8')

requires=[]

if sys.version_info < (3,4):
    requires.append('asyncio')

setup(name='asyncdns2',
      version='0.1.3',
      description='Pure Python asynchronous DNS via asyncio',
      long_description=long_desc,
      author='Alastair Houghton',
      author_email='alastair@alastairs-place.net',
      url='https://alastairs-place.net/projects/asyncdns',
      license='MIT License',
      packages=['asyncdns'],
      classifiers=[
          'Development Status :: 4 - Beta',
          'License :: OSI Approved :: MIT License',
          'Topic :: Internet :: Name Service (DNS)',
          'Framework :: AsyncIO'
          ],
      package_data = {
          'asyncdns': ['named.root']
          },
      scripts=['scripts/pydig'],
      install_requires=requires,
      tests_require=['pytest'],
      cmdclass={
          'test': PyTest
          },
      provides=['asyncdns2'])
