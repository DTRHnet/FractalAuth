# setup.py

from setuptools import setup, find_packages

setup(
    name='FractalAuth',
    version='0.1.0',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    install_requires=[
        'cryptography==3.4.7',
        'paramiko==2.7.2',  # Include if used
    ],
    extras_require={
        'dev': [
            'pytest==6.2.4',
            'pytest-cov==2.12.1',
            'flake8==3.9.2',
            'black==21.7b0',
            'mypy>=1.5.0',  # Updated to eliminate typed-ast dependency
        ],
    },
    author='Your Name',
    author_email='your.email@example.com',
    description='FractalAuth Key Management Module',
    url='https://github.com/yourusername/FractalAuth',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)
