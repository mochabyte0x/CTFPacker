from setuptools import setup, find_packages

setup(
    name='ctfpacker',
    version='1.0',
    description='Cross platform (Linux / Windows) shellcode packer for CTFs and pentest / red team exams',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/mochabyte0x/CTFPacker',
    author='mochabyte0x',
    author_email='contact@mochabyte.xyz',
    maintainer='mochabyte0x',
    license='MIT',
    install_requires=['colorama', 
                      'pycryptodome'],
    py_modules=['main'],
    include_package_data=True,
    packages=find_packages(),
    package_data={'custom_certs':['cert1.pfx', 'cert2.pfx', 'osslsigncode.exe'], 
                  'templates': [
                                'stageless/*', 
                                'staged/*'
                            ]
    },
    entry_points={
        'console_scripts': [
            'ctfpacker=main:main'
        ],
    },
    platforms=['Linux', 'Windows']
)
