from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="netsnoop-monitor",                    # Package name on PyPI
    version="0.2.1",                            # Version number
    author="Chitvi Joshi",                         # Your name
    author_email="chitvijoshi2646@gmail.com",     # Your email
    description="Comprehensive system monitoring with 5 anomaly detectors",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ChitviJoshi/NetSnoop",  # GitHub URL
    project_urls={
        "Bug Tracker": "https://github.com/ChitviJoshi/NetSnoop/issues",
        "Documentation": "https://github.com/ChitviJoshi/NetSnoop/blob/main/README.md",
        "Source Code": "https://github.com/ChitviJoshi/NetSnoop",
    },
    packages=find_packages(),                   # Auto-find packages
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: System :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
        "Operating System :: POSIX :: Linux",
        "Operating System :: Microsoft :: Windows",
    ],
    python_requires=">=3.8",                    # Minimum Python version
    install_requires=requirements,              # Dependencies from requirements.txt
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "black>=22.0.0",
            "flake8>=4.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "netsnoop=netsnoop.cli:main",      # Command-line interface
        ],
    },
    include_package_data=True,                  # Include files from MANIFEST.in
    keywords="monitoring system-monitor anomaly-detection performance cpu memory",
    license="MIT",
)