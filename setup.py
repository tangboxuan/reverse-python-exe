from setuptools import setup

setup(
    name='repyexe',
    version="0.1.2",
    description='Reverse engineer Windows executable file compiled using Python',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='Boxuan Tang',
    author_email='tangboxuan@gmail.com',
    url='https://github.com/tangboxuan/reverse-python-exe',
    packages=['repyexe'],
    install_requires=['pefile', 'uncompyle6'],
    entry_points={
        'console_scripts': [ 'repyexe = repyexe.__main__:main' ]
    },
    keywords='reverse engineer windows executable python malware analysis',
    classifiers=[
        "Natural Language :: English",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent"
    ],
)