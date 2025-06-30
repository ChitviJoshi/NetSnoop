from setuptools import setup, find_packages
from pathlib import Path

# Read README
this_dir = Path(__file__).parent
long_description = (this_dir / "README.md").read_text(encoding="utf-8")

setup(
    name='netsnoop',
    version='0.1.4',  # 👈 bump version
    description='NetSnoop: Real-Time Linux System Anomaly Monitor and Dashboard',
    long_description=long_description,
    long_description_content_type='text/markdown',  # 👈 crucial for PyPI to render it
    author='Chitvi Joshi',
    author_email='chitvijoshi2646@gmail.com',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'streamlit',
        'pandas',
        'plotly'
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'Operating System :: POSIX :: Linux',
        'License :: OSI Approved :: MIT License',
        'Intended Audience :: System Administrators',
        'Topic :: System :: Monitoring',
    ],
    entry_points={
        'console_scripts': [
            'netsnoop-init = netsnoop.setup_runner:main',
        ],
    },
    license='MIT',
    python_requires='>=3.7',
)
