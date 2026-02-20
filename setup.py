from setuptools import find_packages, setup

setup(
    name="skill-quarantine",
    version="0.1.0",
    description="OpenClaw skill security audit tool",
    packages=find_packages(),
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "skill-audit=skill_audit.cli:main",
        ]
    },
    python_requires=">=3.10",
)
