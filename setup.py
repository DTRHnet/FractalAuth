from setuptools import setup, find_packages
import os

# Read the contents of README.md for the long description
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='FractalAuth',
    version='0.1.0',
    packages=find_packages(),
    install_requires=[
        # Add your project dependencies here
        # Example:
        # 'cryptography',
        # 'numpy',
        # 'Pillow',
    ],
    author='KBS',
    author_email='admin@dtrh.net',
    description='A secure Fractal Generator for SSH Key Authentication using Mandelbrot Set',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/your-username/fractalauth',  # Replace with your repository URL
    license='Apache 2.0',
    classifiers=[
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.10',
    entry_points={
        'console_scripts': [
            'fractalauth=src.main:main',  # Adjust if your main function is different
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
