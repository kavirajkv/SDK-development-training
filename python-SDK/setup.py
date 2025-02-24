from setuptools import setup, find_packages

setup(
    name="digitalsignature",
    version="0.2.0",
    description="Python SDK for my digital sign Go backend API",
    author="Kaviraj K",
    author_email="kavirajk36kv@gmmail.com",
    url="https://github.com/kavirajkv/SDK-development-training.git",
    packages=find_packages(),
    install_requires=[
        "requests>=2.25.1",  
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
